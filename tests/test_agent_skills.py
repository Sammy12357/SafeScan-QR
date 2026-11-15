"""Keep project skills discoverable by both Codex and Claude Code."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODEX_SKILLS = ROOT / ".agents" / "skills"
CLAUDE_SKILLS = ROOT / ".claude" / "skills"


def test_project_skills_have_valid_frontmatter_and_matching_copies():
    codex_names = {path.name for path in CODEX_SKILLS.iterdir() if path.is_dir()}
    claude_names = {path.name for path in CLAUDE_SKILLS.iterdir() if path.is_dir()}
    assert codex_names == claude_names
    assert codex_names

    for name in codex_names:
        codex_file = CODEX_SKILLS / name / "SKILL.md"
        claude_file = CLAUDE_SKILLS / name / "SKILL.md"
        assert codex_file.is_file()
        assert claude_file.is_file()
        content = codex_file.read_text()
        assert content == claude_file.read_text()
        parts = content.split("---", 2)
        assert len(parts) == 3 and not parts[0].strip()
        frontmatter = parts[1].strip().splitlines()
        assert frontmatter[0] == f"name: {name}"
        assert len(frontmatter) == 2
        assert frontmatter[1].startswith("description: ")
        assert frontmatter[1].removeprefix("description: ").strip()
