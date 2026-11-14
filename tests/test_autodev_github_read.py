import unittest

from aotg.autodev.github_read import GitHubReadError, PublicGitHubInventory, _next_page

BASE = "/repos/uobnnisiuk/AOTG"
MAIN = "a" * 40
MERGE = "b" * 40
PR_PAGE = BASE + "/pulls?state=open&per_page=100&page=1"
BRANCH_PAGE = BASE + "/branches?per_page=100&page=1"


def branch(name, sha=MAIN):
    return {"name": name, "commit": {"sha": sha}}


def open_pr(number, *, draft=True):
    return {"number": number, "state": "open", "draft": draft}


def initial(*, merged=True, state="closed", repo="uobnnisiuk/AOTG"):
    return {
        "number": 1,
        "state": state,
        "merged": merged,
        "merged_at": "2026-06-01T12:00:00Z" if merged else None,
        "merge_commit_sha": MERGE,
        "base": {"ref": "main", "repo": {"full_name": repo}},
    }


class API:
    def __init__(self, **responses):
        self.replies = {
            BASE + "/branches/main": (branch("main"), False),
            BASE + "/pulls/1": (initial(), False),
            PR_PAGE: ([open_pr(5)], False),
            BRANCH_PAGE: ([branch("autodev/uob-49"), branch("main")], False),
            **responses,
        }
        self.calls = []

    def __call__(self, path):
        testcase = self.replies[path]
        self.calls.append(path)
        return testcase.pop(0) if isinstance(testcase, list) else testcase


class PublicInventoryTests(unittest.TestCase):
    def test_preserves_draft_prs_and_pins_main(self):
        api = API()
        snapshot = PublicGitHubInventory(api).snapshot()
        self.assertEqual(MAIN, snapshot.main_sha)
        self.assertTrue(snapshot.initial_pr_merged)
        self.assertTrue(snapshot.complete)
        self.assertEqual("uobnnisiuk/AOTG", snapshot.repo)
        self.assertEqual((5,), snapshot.open_pr_numbers)
        self.assertEqual(("autodev/uob-49", "main"), snapshot.branch_names)
        self.assertEqual(2, api.calls.count(BASE + "/branches/main"))

    def test_initial_pr_can_be_open_or_closed_without_merging(self):
        for state in ("open", "closed"):
            api = API(**{
                BASE + "/pulls/1": (initial(merged=False, state=state), False),
                PR_PAGE: ([open_pr(1)] if state == "open" else [], False),
            })
            with self.subTest(state=state):
                self.assertFalse(PublicGitHubInventory(api).snapshot().initial_pr_merged)

    def test_reads_all_open_prs_and_branches_when_pages_are_full(self):
        api = API(**{
            PR_PAGE: ([open_pr(i, draft=(i == 100)) for i in range(5, 105)], True),
            BASE + "/pulls?state=open&per_page=100&page=2": ([open_pr(105)], False),
            BRANCH_PAGE: ([branch(f"branch-{i}") for i in range(100)], True),
            BASE + "/branches?per_page=100&page=2": ([branch("main")], False),
        })
        snapshot = PublicGitHubInventory(api).snapshot()
        self.assertEqual(tuple(range(5, 106)), snapshot.open_pr_numbers)
        self.assertEqual(101, len(snapshot.branch_names))

    def test_rejects_partial_duplicated_and_malformed_lists(self):
        for response in (
            ({"items": []}, False),
            ([open_pr(5)], True),
            ([open_pr(5), open_pr(5)], False),
            ([open_pr(5), open_pr(1)], False),
            ([open_pr(5, draft="yes")], False),
            ([{"number": 5, "state": "closed", "draft": False}], False),
            ([open_pr(5)], 0),
        ):
            with self.subTest(response=response), self.assertRaises(GitHubReadError):
                PublicGitHubInventory(API(**{PR_PAGE: response})).snapshot()

    def test_rejects_too_many_pages_instead_of_returning_a_partial_list(self):
        api = API(**{
            BASE + f"/pulls?state=open&per_page=100&page={page}": (
                [open_pr(page * 100 + row) for row in range(100)],
                True,
            )
            for page in range(1, 5)
        })
        with self.assertRaisesRegex(GitHubReadError, "page limit"):
            PublicGitHubInventory(api).snapshot()
        self.assertEqual(4, sum("state=open" in path for path in api.calls))

    def test_rejects_an_unconfirmed_initial_merge(self):
        for pr in (
            initial(merged=True, state="open"),
            initial(repo="other/AOTG"),
            {**initial(), "merged_at": None},
            {**initial(), "merge_commit_sha": None},
            {**initial(), "number": True},
        ):
            with self.subTest(pr=pr), self.assertRaises(GitHubReadError):
                PublicGitHubInventory(API(**{BASE + "/pulls/1": (pr, False)})).snapshot()

    def test_rejects_changed_open_inventory(self):
        api = API(**{PR_PAGE: [([open_pr(5)], False), ([open_pr(6)], False)]})
        with self.assertRaisesRegex(GitHubReadError, "state changed"):
            PublicGitHubInventory(api).snapshot()

    def test_rejects_malformed_or_changing_main(self):
        for responses in (
            {BASE + "/branches/main": (branch("main", "0" * 40), False)},
            {BASE + "/branches/main": (branch("other"), False)},
            {BASE + "/branches/main": (branch("main"), True)},
            {BRANCH_PAGE: ([branch("main", MERGE)], False)},
            {BRANCH_PAGE: ([branch("main"), branch("main")], False)},
            {BASE + "/branches/main": [(branch("main"), False), (branch("main", MERGE), False)]},
        ):
            with self.subTest(responses=responses), self.assertRaises(GitHubReadError):
                PublicGitHubInventory(API(**responses)).snapshot()


class PaginationTests(unittest.TestCase):
    def test_accepts_only_exact_next_page_from_same_repo(self):
        canonical = "https://api.github.com" + PR_PAGE.removesuffix("page=1") + "page=2"
        header = f'<{canonical}>; rel="next", <{canonical}>; rel="last"'
        self.assertTrue(_next_page(header, PR_PAGE))
        self.assertFalse(_next_page(f'<{canonical}>; rel="prev"', PR_PAGE))
        self.assertFalse(_next_page("", PR_PAGE))

    def test_rejects_redirect_origins_and_query_manipulation(self):
        canonical = "https://api.github.com" + PR_PAGE.removesuffix("page=1") + "page=2"
        for value in (
            canonical.replace("https://", "http://"),
            canonical.replace("api.github.com", "example.test"),
            canonical.replace("/AOTG/", "/other/"),
            canonical.replace("state=open", "state=closed"),
            canonical.replace("page=2", "page=3"),
            canonical + "#fragment",
            canonical + "&page=2",
        ):
            with self.subTest(value=value), self.assertRaises(GitHubReadError):
                _next_page(f'<{value}>; rel="next"', PR_PAGE)

    def test_rejects_duplicate_and_unparseable_pagination_metadata(self):
        canonical = "https://api.github.com" + PR_PAGE.removesuffix("page=1") + "page=2"
        next_link = f'<{canonical}>; rel="next"'
        for header in ("bad", next_link + ", " + next_link):
            with self.subTest(header=header), self.assertRaises(GitHubReadError):
                _next_page(header, PR_PAGE)


if __name__ == "__main__":
    unittest.main()