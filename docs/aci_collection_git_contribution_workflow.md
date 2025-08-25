# Git contribution workflow for ACI collection

To contribute to the Cisco ACI Ansible Collection, follow the standard Git workflow: Fork → Clone → Branch. This ensures clean code isolation, proper tracking of changes, and allows seamless contributions via pull requests. Fork and clone tasks are carried out just once.
The collection code is located in a git repository (https://github.com/CiscoDevNet/ansible-aci).

**Step1: Fork the repository**

A Fork is a personal copy of the repository under your GitHub account, allowing you to make changes without affecting the upstream project.

Steps to create a fork of the repository:
* Navigate to: https://github.com/CiscoDevNet/ansible-aci
* Click the *Fork* button in the upper-right corner to create your fork of the CiscoDevNet's **ansible-aci** repo

  Refer to GitHub's official guide of [How to fork a repo](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo)

**Step2: Clone the forked repository**

Clone allows to copy a repository to the local machine.

* Clone the forked repository in the terminal using the following command:

```text
git clone https://github.com/<Forked Organization>/ansible-aci.git
```

Verify the name of the Git remote of your forked repository by running the following commands in the terminal:

```text
cd ansible-aci
git remote -v
```

Expected output:

```text
origin        https://github.com/<Forked Organization>/ansible-aci.git (fetch)
origin        https://github.com/<Forked Organization>/ansible-aci.git (push)
```

**Naming Convention**
"origin" is the default name for the first Git remote of a cloned repository. In this case, it represents your forked repo where you are going to make changes, commit, and push your code to GitHub.

* Add the upstream repo as a new Git remote:

To be able to retrieve the latest changes made to the upstream project repo (CiscoDevNet/ansible-aci), we need to add it as a second Git remote. We recommend calling this second remote "upstream" and we will keep referring to it as upstream in the rest of the document.
Add the original CiscoDevNet repository (CiscoDevNet/ansible-aci) as a second remote named `upstream`, which will allow the fetch, and sync the latest changes:

```text
git remote add upstream https://github.com/CiscoDevNet/ansible-aci.git
```

Adding the remote branch "upstream" is a one-time operation.
After adding the upstream remote, update the local repository with the latest changes from the upstream repository:

* Fetch and update the local `master` branch from upstream:

```text
git checkout master
git pull upstream master
```

**Step 3: Create a Feature Branch**

Branch facilitates bug fixes, addition of new features, and the integration of new versions after isolated testing. Master is the default branch of the local repository.
Each time changes are required for a module or a new module is to be created, it is recommended that a new dedicated branch be created from master. This provides a clean branch of the latest master, enabling all necessary modifications to be made.

* Create a branch from master by using the following commands on the terminal:

```text
git checkout master
git checkout -b <new-branch-name>
```

Maintaining changes in a dedicated branch allows the master branch to remain clean and synchronized with the upstream master. This simplifies keeping the local master branch updated without the need to merge code or rebase the master branch.

> [!CAUTION]
> Never commit directly to `master`. Use feature branches for all development work to simplify merging, testing, and collaboration.
