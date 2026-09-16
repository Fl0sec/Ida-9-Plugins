"""Golden vectors: resolve real CFS6 candidates against real cs2 client.dll.

These are the tests that prove the contract is implementable without IDA and
that a signature exported from one build still resolves on the next. They skip
cleanly when the DLLs are not on this machine.

Vector 1 -- ConVarRef_GetFloat, REL, exported from build 14177. The dumper's
handwritten pattern broke on 14181; this candidate must still resolve, and must
resolve to RVA 0x167050.

Vector 2 -- TraceShape, BODY. Must map back to its owning .pdata runtime
function in both builds via body_offset.
"""

import os
import struct
import tempfile
import unittest

from _support import (
    body_candidate, dll_path, have_dll, rel_candidate, write_cfs6,
)

from cfs5 import cfs6
from cfs5.peinfo import PdataIndex, PeImage, detect_build_from_path

import cfs6_resolve


# Exported from build 14177 by the CFS5 exporter, transcribed into CFS6 fields:
#   CFS2,4,0,ConVarRef_GetFloat,REL,0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50,
#        target_delta=0 rel_offset=4 rel_size=4 base_offset=8 insn_offset=3
CONVARREF_PATTERN = "0F 28 F0 E8 ? ? ? ? 48 8B 6C 24 50"
CONVARREF_RESOLVE = dict(insn_offset=3, disp_offset=4, disp_size=4, base_offset=8)
CONVARREF_TARGET_14181 = 0x167050

TRACESHAPE_PATTERN = "48 8B F3 48 8B 45 B8 48 8B 0C 30"
TRACESHAPE_BODY_OFFSET = 0x1C9


def requires(build):
    return unittest.skipUnless(
        have_dll(build), "client.dll for build %s is not on this machine" % build
    )


class GoldenCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def image(self, build):
        return PeImage.from_path(dll_path(build))

    def convarref_candidate(self, **overrides):
        kwargs = dict(CONVARREF_RESOLVE)
        kwargs.update(overrides)
        return rel_candidate(
            CONVARREF_PATTERN, anchor=0,
            insn_offset=kwargs["insn_offset"],
            disp_offset=kwargs["disp_offset"],
            disp_size=kwargs["disp_size"],
            base_offset=kwargs["base_offset"],
        )


@requires("14181")
class TestConVarRefGetFloat(GoldenCase):
    """The headline case: a 14177 REL signature resolving on 14181."""

    def test_pattern_is_unique_in_14181(self):
        image = self.image("14181")
        rva, error = cfs6_resolve.find_unique_match(image, CONVARREF_PATTERN)
        self.assertIsNone(error)
        self.assertEqual(rva, 0x16B807)

    def test_resolves_to_0x167050(self):
        image = self.image("14181")
        target, error = cfs6_resolve.resolve(image, self._loaded_candidate())
        self.assertIsNone(error)
        self.assertEqual(target, CONVARREF_TARGET_14181)

    def test_anchor_is_a_call_rel32(self):
        """instruction_offset must point at the E8 that owns the field."""
        image = self.image("14181")
        rva, _ = cfs6_resolve.find_unique_match(image, CONVARREF_PATTERN)
        opcode = image.read(rva + CONVARREF_RESOLVE["insn_offset"], 1)
        self.assertEqual(opcode, b"\xe8")

    def test_target_is_executable(self):
        image = self.image("14181")
        target, _ = cfs6_resolve.resolve(image, self._loaded_candidate())
        self.assertTrue(image.is_executable_rva(target))

    def test_target_delta_is_applied(self):
        image = self.image("14181")
        cand = self._loaded_candidate(target_delta=16)
        target, error = cfs6_resolve.resolve(image, cand)
        self.assertIsNone(error)
        self.assertEqual(target, CONVARREF_TARGET_14181 + 16)

    def test_corrupted_base_offset_is_rejected(self):
        """base_offset must be stored, not inferred -- a wrong one must fail."""
        image = self.image("14181")
        # base_offset 6 ends the anchor instruction before its own 4-byte
        # displacement field does, so the boundary check must reject it.
        cand = self._loaded_candidate(base_offset=6, skip_load_validation=True)
        _target, error = cfs6_resolve.resolve(image, cand)
        self.assertIsNotNone(error)
        self.assertIn("outside the anchor instruction", error)

    def test_wrong_base_offset_yields_a_different_target(self):
        """Proves base_offset genuinely participates in the arithmetic."""
        image = self.image("14181")
        good, _ = cfs6_resolve.resolve(image, self._loaded_candidate())
        drifted, error = cfs6_resolve.resolve(
            image, self._loaded_candidate(base_offset=9, skip_load_validation=True)
        )
        self.assertIsNone(error)
        self.assertEqual(drifted, good + 1)

    def _loaded_candidate(self, target_delta=0, skip_load_validation=False,
                          **overrides):
        """Round-trip through a real CFS6 file so the file format is in play."""
        cand = self.convarref_candidate(**overrides)
        cand.target_delta = target_delta

        if skip_load_validation:
            # The reader deliberately rejects these shapes; build the record
            # directly so the *resolver's* own boundary check is what fires.
            resolve = cand.resolve_object()
            return cfs6.CandidateRecord(
                line_no=0, item="fn:x", rank=0, mode="REL",
                pattern=CONVARREF_PATTERN, resolve=resolve,
            )

        path = os.path.join(self.dir.name, "g.cfs")
        write_cfs6(path, [(cfs6.REC_FUNCTION, "ConVarRef_GetFloat", [cand])])
        loaded = cfs6.load_cfs6(path)
        self.assertEqual(loaded.parse_errors, 0)
        return loaded.functions()[0].candidates[0]


class TestTraceShapeBodyOwnership(GoldenCase):
    """BODY resolution via .pdata, in both builds."""

    def _check(self, build):
        image = self.image(build)
        rva, error = cfs6_resolve.find_unique_match(image, TRACESHAPE_PATTERN)
        self.assertIsNone(error, "pattern not unique in %s" % build)

        cand = body_candidate(
            TRACESHAPE_PATTERN,
            anchor=0x1000 + TRACESHAPE_BODY_OFFSET,
            func=0x1000,
        )
        self.assertEqual(cand.body_offset, TRACESHAPE_BODY_OFFSET)

        target, error = cfs6_resolve.resolve(image, _as_record(cand))
        self.assertIsNone(error)
        self.assertEqual(target, rva - TRACESHAPE_BODY_OFFSET)
        self.assertTrue(image.is_runtime_function_start(target))

        owning = image.runtime_function_containing(rva)
        self.assertIsNotNone(owning)
        self.assertEqual(owning[0], target)

    @requires("14177")
    def test_resolves_in_14177(self):
        self._check("14177")

    @requires("14181")
    def test_resolves_in_14181(self):
        self._check("14181")

    @requires("14181")
    def test_body_offset_off_by_one_is_rejected(self):
        """A hit that does not land on a .pdata start must not resolve."""
        image = self.image("14181")
        cand = body_candidate(
            TRACESHAPE_PATTERN,
            anchor=0x1000 + TRACESHAPE_BODY_OFFSET + 1,
            func=0x1000,
        )
        target, error = cfs6_resolve.resolve(image, _as_record(cand))
        self.assertIsNone(target)
        self.assertIn("not a .pdata runtime-function start", error)

    @requires("14181")
    def test_ida_only_ownership_is_skipped_not_guessed(self):
        """A BODY the exporter marked unresolvable must not be resolved anyway."""
        image = self.image("14181")
        cand = body_candidate(
            TRACESHAPE_PATTERN,
            anchor=0x1000 + TRACESHAPE_BODY_OFFSET,
            func=0x1000,
        )
        cand.ownership = "ida-only"
        target, error = cfs6_resolve.resolve(image, _as_record(cand))
        self.assertIsNone(target)
        self.assertIn("not resolvable from .pdata", error)

    @requires("14181")
    def test_unknown_ownership_value_is_skipped(self):
        image = self.image("14181")
        cand = body_candidate(
            TRACESHAPE_PATTERN,
            anchor=0x1000 + TRACESHAPE_BODY_OFFSET,
            func=0x1000,
        )
        cand.ownership = "some-future-scheme"
        target, _error = cfs6_resolve.resolve(image, _as_record(cand))
        self.assertIsNone(target)

    @requires("14181")
    def test_body_offset_stayed_stable_across_builds(self):
        """The interior offset survived the build; that is why BODY works."""
        rvas = {}
        for build in ("14177", "14181"):
            if not have_dll(build):
                self.skipTest("need both builds")
            image = self.image(build)
            rva, error = cfs6_resolve.find_unique_match(image, TRACESHAPE_PATTERN)
            self.assertIsNone(error)
            owning = image.runtime_function_containing(rva)
            rvas[build] = rva - owning[0]
        self.assertEqual(rvas["14177"], rvas["14181"])
        self.assertEqual(rvas["14181"], TRACESHAPE_BODY_OFFSET)


@requires("14181")
class TestPeIdentity(GoldenCase):
    def test_header_identity_matches_the_real_pe(self):
        identity = self.image("14181").identity()
        self.assertEqual(identity["architecture"], "x86_64")
        self.assertEqual(identity["timestamp"], 0x6AA1AE5E)
        self.assertEqual(identity["size_of_image"], 0x27DE000)
        self.assertEqual(len(identity["sha256"]), 64)
        self.assertEqual(identity["format"], "PE")

    def test_pdata_is_populated(self):
        self.assertGreater(self.image("14181").runtime_function_count, 100000)

    def test_build_detection_from_the_real_path(self):
        number, source = detect_build_from_path(dll_path("14181"))
        self.assertEqual(number, 14181)
        self.assertEqual(source, "path-detected")


@requires("14181")
class TestMappedImageView(GoldenCase):
    """A mapped (RVA-addressed) view must agree with the file view exactly.

    This is what the exporter uses when it reads the PE headers out of IDA's
    HEADER segment instead of the file on disk. Here the "mapping" is built
    from the real file so the two can be compared directly.
    """

    def mapped(self):
        image = self.image("14181")
        raw = image.data

        def read(rva, size):
            # A loader maps the header region (file offset 0) at RVA 0, then
            # each section at its own RVA. Reproduce both.
            if rva < 0x1000:
                return raw[rva:rva + size]
            return image.read(rva, size)

        return PeImage.from_rva_reader(read, name="client.dll")

    def test_headers_match_the_file_view(self):
        disk, mapped = self.image("14181"), self.mapped()
        self.assertTrue(mapped.virtual)
        self.assertFalse(disk.virtual)
        self.assertEqual(mapped.architecture, disk.architecture)
        self.assertEqual(mapped.timestamp, disk.timestamp)
        self.assertEqual(mapped.size_of_image, disk.size_of_image)
        self.assertEqual(len(mapped.sections), len(disk.sections))

    def test_pdata_matches_the_file_view(self):
        disk, mapped = self.image("14181"), self.mapped()
        self.assertEqual(
            mapped.runtime_function_count, disk.runtime_function_count
        )
        self.assertGreater(mapped.runtime_function_count, 100000)
        for rva in (CONVARREF_TARGET_14181, 0x9E6114):
            self.assertEqual(
                mapped.runtime_function_containing(rva),
                disk.runtime_function_containing(rva),
            )
            self.assertEqual(
                mapped.is_runtime_function_start(rva),
                disk.is_runtime_function_start(rva),
            )

    def test_mapped_view_has_no_file_digest(self):
        """A mapped image cannot hash file bytes; the caller supplies it."""
        mapped = self.mapped()
        self.assertIsNone(mapped.sha256())
        identity = mapped.identity(sha256="ab" * 32)
        self.assertEqual(identity["sha256"], "ab" * 32)
        self.assertEqual(identity["size_of_image"], 0x27DE000)

    def test_rejects_a_reader_without_mz(self):
        with self.assertRaises(Exception):
            PeImage.from_rva_reader(lambda rva, size: b"\x00" * size)


@requires("14181")
class TestPdataFromSegmentBytes(GoldenCase):
    """`.pdata` recovered without PE headers must equal the header-derived one.

    This is the path used on an IDB that has a `.pdata` segment but no mapped
    `HEADER` segment -- otherwise every BODY candidate would be needlessly
    downgraded to `ida-only`.
    """

    def test_segment_bytes_reproduce_the_index(self):
        image = self.image("14181")
        from_headers = image.pdata_index

        rva, size = image._pdata_dir
        raw = image.read(rva, size)
        from_segment = PdataIndex.from_bytes(raw)

        self.assertEqual(from_segment.count, from_headers.count)
        self.assertGreater(from_segment.count, 100000)
        for probe in (CONVARREF_TARGET_14181, 0x9E6114, 0x9E62DD):
            self.assertEqual(
                from_segment.containing(probe), from_headers.containing(probe)
            )
            self.assertEqual(
                from_segment.is_start(probe), from_headers.is_start(probe)
            )

    def test_empty_index_is_safe(self):
        empty = PdataIndex()
        self.assertEqual(empty.count, 0)
        self.assertIsNone(empty.containing(0x1000))
        self.assertFalse(empty.is_start(0x1000))
        self.assertEqual(PdataIndex.from_bytes(b"").count, 0)
        self.assertEqual(PdataIndex.from_bytes(None).count, 0)

    def test_degenerate_entries_are_dropped(self):
        # end <= begin is not a function.
        raw = struct.pack("<III", 0x2000, 0x2000, 0) + \
              struct.pack("<III", 0x3000, 0x2000, 0) + \
              struct.pack("<III", 0x1000, 0x1100, 0)
        index = PdataIndex.from_bytes(raw)
        self.assertEqual(index.count, 1)
        self.assertTrue(index.is_start(0x1000))
        self.assertIsNone(index.containing(0x2000))

    def test_gap_between_functions_belongs_to_neither(self):
        raw = struct.pack("<III", 0x1000, 0x1100, 0) + \
              struct.pack("<III", 0x2000, 0x2100, 0)
        index = PdataIndex.from_bytes(raw)
        self.assertIsNone(index.containing(0x1500))
        self.assertEqual(index.containing(0x1050), (0x1000, 0x1100))


class TestBuildDetection(unittest.TestCase):
    def test_ambiguous_path_yields_unknown(self):
        number, source = detect_build_from_path(r"C:\a\14177\b\14181\client.dll")
        self.assertIsNone(number)
        self.assertEqual(source, "unknown")

    def test_no_numeric_component_yields_unknown(self):
        number, source = detect_build_from_path(r"C:\games\cs2\client.dll")
        self.assertIsNone(number)
        self.assertEqual(source, "unknown")

    def test_filename_alone_is_not_a_build(self):
        number, _source = detect_build_from_path(r"C:\games\14177.dll")
        self.assertIsNone(number)

    def test_empty_path(self):
        self.assertEqual(detect_build_from_path(""), (None, "unknown"))


def _as_record(cand):
    return cfs6.CandidateRecord(
        line_no=0, item="fn:x", rank=0, mode=cand.mode,
        pattern=cand.signature, origin=cand.origin,
        source=cand.source_object(), resolve=cand.resolve_object(),
    )


if __name__ == "__main__":
    unittest.main()
