"""IDA-free patch-site declaration model."""

from .declare import DeclarationError, _check_identifier


class PatchDeclaration:
    __slots__ = ("owner", "name", "ea", "expected_instruction",
                 "expected_bytes", "patch_size")

    def __init__(self, owner, name, site):
        if not isinstance(site, dict):
            raise DeclarationError("patch site must be an object")
        self.owner = _check_identifier("owner", owner)
        self.name = _check_identifier("name", name)
        self.ea = int(site.get("ea", 0))
        self.expected_instruction = str(
            site.get("expected_instruction", "")
        ).strip().lower()
        raw = str(site.get("expected_bytes", "")).replace(" ", "").upper()
        try:
            bytes.fromhex(raw)
        except ValueError:
            raise DeclarationError("expected_bytes must be hexadecimal")
        self.expected_bytes = raw
        self.patch_size = int(site.get("patch_size", 0))
        if not self.ea or not self.expected_instruction or not raw:
            raise DeclarationError("patch site needs ea, instruction and bytes")
        if self.patch_size <= 0:
            raise DeclarationError("patch_size must be positive")
        if self.patch_size < len(bytes.fromhex(raw)):
            raise DeclarationError("patch_size is smaller than expected_bytes")

    @property
    def id(self):
        return "patch:%s::%s" % (self.owner, self.name)

    @property
    def qualified(self):
        return "%s::%s" % (self.owner, self.name)

    def to_dict(self):
        return {
            "owner": self.owner, "name": self.name, "ea": self.ea,
            "expected_instruction": self.expected_instruction,
            "expected_bytes": self.expected_bytes,
            "patch_size": self.patch_size,
        }


def from_dict(data):
    return PatchDeclaration(data.get("owner"), data.get("name"), {
        "ea": data.get("ea"),
        "expected_instruction": data.get("expected_instruction"),
        "expected_bytes": data.get("expected_bytes"),
        "patch_size": data.get("patch_size"),
    })
