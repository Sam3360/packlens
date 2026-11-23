from __future__ import annotations

from helpers import Symlink, make_tar, make_zip
from packlens.analysis.tree import build_tree, iter_tree
from packlens.core.archive import open_archive


def tree_of(path, depth=None):
    with open_archive(path) as handler:
        root = build_tree(handler.entries())
    return root, list(iter_tree(root, max_depth=depth))


def test_hierarchy_and_ordering(tmp_path, sample):
    root, lines = tree_of(make_zip(tmp_path / "a.zip", sample))
    names = [(l.depth, l.node.name) for l in lines]
    # directories first, then files, each alphabetical
    assert names == [(1, "docs"), (2, "guide.txt"), (1, "src"), (2, "main.py"), (2, "util.py"), (1, "README.md")]
    assert root.total_size == sum(len(v) for v in sample.values() if v)


def test_explicit_and_implicit_directories_are_not_duplicated(tmp_path):
    # "a/" is listed explicitly *and* implied by "a/b.txt" and "./a/c.txt"
    root, lines = tree_of(make_tar(tmp_path / "a.tar", {"a/": None, "a/b.txt": b"1", "./a/c.txt": b"22"}))
    assert [l.node.name for l in lines].count("a") == 1
    assert root.total_size == 3


def test_implicit_parents_are_created(tmp_path):
    _, lines = tree_of(make_zip(tmp_path / "a.zip", {"x/y/z.txt": b"1"}))
    assert [l.node.name for l in lines] == ["x", "y", "z.txt"]


def test_depth_limit_summarises_hidden_content(tmp_path):
    _, lines = tree_of(make_zip(tmp_path / "a.zip", {"a/b/c/d.txt": b"1234", "a/b/e.txt": b"5"}), depth=2)
    assert [l.node.name for l in lines] == ["a", "b"]
    assert lines[1].hidden == 3 and lines[1].hidden_size == 5


def test_very_deep_paths_do_not_hit_recursion_limits(tmp_path):
    deep = "/".join(f"d{i}" for i in range(3000)) + "/leaf.txt"
    root, lines = tree_of(make_tar(tmp_path / "deep.tar", {deep: b"x"}))
    assert len(lines) == 3001 and lines[-1].node.name == "leaf.txt"
    assert root.total_size == 1


def test_repeated_file_paths_are_marked(tmp_path):
    root, lines = tree_of(make_tar(tmp_path / "a.tar", [("f", b"1"), ("f", b"22")]))
    assert lines[0].node.repeats == 1


def test_file_and_directory_conflict_is_marked(tmp_path):
    _, lines = tree_of(make_tar(tmp_path / "a.tar", {"x": b"file", "x/inner": b"1"}))
    assert next(l for l in lines if l.node.name == "x").node.conflict


def test_symlink_node_keeps_target(tmp_path):
    _, lines = tree_of(make_tar(tmp_path / "a.tar", {"l": Symlink("target")}))
    assert lines[0].node.entry.link_target == "target"


def test_ascii_prefixes(tmp_path, sample):
    with open_archive(make_zip(tmp_path / "a.zip", sample)) as handler:
        lines = list(iter_tree(build_tree(handler.entries()), max_depth=None, ascii_only=True))
    assert all(l.prefix.isascii() for l in lines)
