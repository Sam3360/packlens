"""Directory-tree model built from entry paths. Iterative throughout: path depth is untrusted."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from packlens.core.models import ArchiveEntry, EntryType


@dataclass(slots=True)
class TreeNode:
    name: str
    entry: ArchiveEntry | None = None  # the entry stored at exactly this path (first one wins)
    children: dict[str, "TreeNode"] | None = None
    is_dir: bool = False
    repeats: int = 0  # how many *additional* file entries share this exact path
    conflict: bool = False  # stored as both a file and a directory
    total_size: int = 0
    descendants: int = 0


@dataclass(slots=True)
class TreeLine:
    node: TreeNode
    path: str
    depth: int
    prefix: str  # box-drawing prefix including the connector
    hidden: int  # descendants not shown because of the depth limit
    hidden_size: int


def build_tree(entries: Iterable[ArchiveEntry]) -> TreeNode:
    root = TreeNode("", is_dir=True, children={})
    for entry in entries:
        parts = [p for p in entry.path.split("/") if p not in ("", ".")]
        if not parts:
            continue
        node = root
        for part in parts[:-1]:
            if node.children is None:
                node.children = {}
            child = node.children.get(part)
            if child is None:
                child = node.children[part] = TreeNode(part, is_dir=True)
            elif not child.is_dir:
                child.conflict = True
                child.is_dir = True
            node = child
        if node.children is None:
            node.children = {}
        leaf = node.children.get(parts[-1])
        is_dir = entry.type is EntryType.DIRECTORY
        if leaf is None:
            leaf = node.children[parts[-1]] = TreeNode(parts[-1], entry=entry, is_dir=is_dir)
        else:
            if leaf.entry is None:
                leaf.entry = entry
            elif not is_dir:
                if leaf.entry.type is EntryType.DIRECTORY:
                    leaf.entry = entry
                    leaf.conflict = True
                else:
                    leaf.repeats += 1
            if not is_dir and leaf.is_dir and leaf.children:
                leaf.conflict = True
            if is_dir:
                leaf.is_dir = True
            elif leaf.children:
                leaf.is_dir = True
    _aggregate(root)
    return root


def _aggregate(root: TreeNode) -> None:
    """Compute subtree sizes and descendant counts without recursion."""
    order = [root]
    parent: dict[int, TreeNode] = {}
    index = 0
    while index < len(order):
        node = order[index]
        index += 1
        if node.children:
            for child in node.children.values():
                parent[id(child)] = node
                order.append(child)
    for node in reversed(order):
        if node.entry is not None and node.entry.type is EntryType.FILE and node.entry.size:
            node.total_size += node.entry.size
        up = parent.get(id(node))
        if up is not None:
            up.total_size += node.total_size
            up.descendants += node.descendants + 1


def _sort_key(node: TreeNode) -> tuple[bool, str]:
    return (not node.is_dir, node.name)


def iter_tree(root: TreeNode, *, max_depth: int | None, ascii_only: bool = False) -> Iterator[TreeLine]:
    """Pre-order traversal with explicit stack. Top-level entries have depth 1."""
    branch, last, pipe, blank = ("|-- ", "`-- ", "|   ", "    ") if ascii_only else ("├── ", "└── ", "│   ", "    ")
    stack: list[tuple[TreeNode, str, str, bool, int]] = []  # node, parent path, parent prefix, is_last, depth

    def push_children(node: TreeNode, path: str, prefix: str, depth: int) -> None:
        kids = sorted(node.children.values(), key=_sort_key) if node.children else []
        for position in range(len(kids) - 1, -1, -1):
            stack.append((kids[position], path, prefix, position == len(kids) - 1, depth))

    push_children(root, "", "", 1)
    while stack:
        node, parent_path, parent_prefix, is_last, depth = stack.pop()
        path = f"{parent_path}/{node.name}" if parent_path else node.name
        connector = last if is_last else branch
        show_children = bool(node.children) and (max_depth is None or depth < max_depth)
        hidden = node.descendants if node.children and not show_children else 0
        hidden_size = node.total_size if hidden else 0
        yield TreeLine(node, path, depth, parent_prefix + connector, hidden, hidden_size)
        if show_children:
            push_children(node, path, parent_prefix + (blank if is_last else pipe), depth + 1)
