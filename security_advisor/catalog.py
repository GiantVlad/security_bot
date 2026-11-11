"""Broad user-facing groups mapped to OSV package ecosystems."""

GROUPS: dict[str, tuple[str, ...]] = {
    "JavaScript / TypeScript": ("npm",),
    "Python": ("PyPI",),
    "Java": ("Maven",),
    "PHP": ("Packagist",),
    "Go": ("Go",),
    "Rust": ("crates.io",),
    "Ruby": ("RubyGems",),
    ".NET": ("NuGet",),
}

GROUP_BY_ECOSYSTEM = {
    ecosystem: group for group, ecosystems in GROUPS.items() for ecosystem in ecosystems
}
