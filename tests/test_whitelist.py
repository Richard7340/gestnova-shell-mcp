from gestnova_shell.whitelist import is_allowed, categories_listing


def test_categories_listing_has_expected_categories():
    cats = {c["category"] for c in categories_listing()}
    assert {"read", "git_read", "build", "python_safe", "finance_tools"} <= cats


def test_read_category_allows_ls():
    ok, reason = is_allowed("read", ["ls", "-la"])
    assert ok, reason


def test_read_category_rejects_rm():
    ok, reason = is_allowed("read", ["rm", "-rf", "/"])
    assert not ok
    assert "not allowed" in reason


def test_git_read_allows_status():
    ok, reason = is_allowed("git_read", ["git", "status"])
    assert ok, reason


def test_git_read_rejects_push():
    ok, reason = is_allowed("git_read", ["git", "push"])
    assert not ok
    assert "forbidden" in reason.lower()


def test_git_read_rejects_commit():
    ok, reason = is_allowed("git_read", ["git", "commit", "-m", "test"])
    assert not ok


def test_build_allows_pytest():
    ok, _ = is_allowed("build", ["pytest", "-q"])
    assert ok


def test_build_rejects_npm_publish():
    ok, reason = is_allowed("build", ["npm", "publish"])
    assert not ok
    assert "publish" in reason.lower()


def test_python_safe_rejects_dash_c():
    ok, reason = is_allowed("python_safe", ["python", "-c", "import os; os.system('rm -rf /')"])
    assert not ok


def test_global_pattern_blocks_shell_metacharacters():
    ok, reason = is_allowed("read", ["ls", "|", "rm"])
    assert not ok


def test_global_pattern_blocks_path_traversal():
    ok, reason = is_allowed("read", ["cat", "../../etc/passwd"])
    assert not ok


def test_unknown_category_rejected():
    ok, reason = is_allowed("hack", ["ls"])
    assert not ok
    assert "unknown category" in reason
