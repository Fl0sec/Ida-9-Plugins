// Optimized MSVC RTTI fixture. Build as x86 and x64 with /GR /O2.

#include <typeinfo>

struct Root {
    virtual ~Root() = default;
    virtual int root() { return 1; }
};

struct Left : virtual Root {
    virtual int left() { return 2; }
};

struct Right : virtual Root {
    virtual int right() { return 3; }
};

struct Diamond final : Left, Right {
    int root() override { return 4; }
    int left() override { return 5; }
    int right() override { return 6; }
    virtual int own() { return 7; }
};

__declspec(noinline) int dispatch(Root *root) {
    Right *right = dynamic_cast<Right *>(root);
    return root->root() + (right ? right->right() : 0)
        + typeid(*root).name()[0];
}

int main(int argc, char **) {
    Root root_value;
    Left left_value;
    Right right_value;
    Diamond value;
    Root *root = &value;
    return dispatch(&root_value) + dispatch(&left_value)
        + dispatch(&right_value) + dispatch(root) + argc;
}
