"""Exercise the disabled, local Go Ghost interpreter in the existing CI test job."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_offline_recipe_interpreter():
    subprocess.run(["node", "tests/go_ghost_recipe.test.js"], cwd=ROOT, check=True)


def test_no_live_broker_recipes_or_extension_entrypoint():
    recipes = ROOT / "extension" / "recipes"
    assert {path.name for path in recipes.iterdir()} == {"schema.json"}
    assert not (ROOT / "extension" / "manifest.json").exists()
