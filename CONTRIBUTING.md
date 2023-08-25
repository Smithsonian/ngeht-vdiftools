# Contributing

Per [GitLab Flow](https://docs.gitlab.com/ee/workflow/gitlab_flow.html), all development should take place on a branch created specifically for each change that is being implemented.  This allows for multiple changes to be implemented independently without conflicting, and also allows a developer to work on a release hotfix without danger of accidentally merging new features to a live release.

1. Determine the branch from which to create the development branch

1. Create the development branch in GitHub according to the following conventions:

    |Branch type|Example name|Description|
    |-|-|-|
    | change | _issue-id_ | Branches associated with an issue assigned from the issue tracking system. _issue-id_ is the ID assigned from the issue tracking system. |
    | experimental | _username_/_string_ | Branches for experimental code not associated with an issue. _string_ is a short description of the work being performed. |

1. Perform iterative implementation & test

    * Push commits regularly to both protect against code loss due to a failing local disk and also to allow others to see progress if they choose

    * Only rebase/squash commits that __have not been pushed__

1. Ensure all assigned success criteria are satisfied, including the following:

    * _TODO - List criteria to satisfy/tests to pass_

1. Open a pull request to merge the development branch back to the appropriate target branch.