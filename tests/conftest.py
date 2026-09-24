import pytest


@pytest.fixture
def repo(tmp_path):
    """A checkout builder: `repo.write("a/b.txt", "...")` then `repo.scan()`."""
    class Checkout:
        root = tmp_path

        def write(self, rel, text):
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            return path

        def scan(self):
            from immunis.checks import run
            return run(tmp_path)

        def named(self, check):
            return [f for f in self.scan() if f.check == check]

    return Checkout()
