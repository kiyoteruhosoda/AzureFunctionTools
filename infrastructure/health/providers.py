from __future__ import annotations

import os
import subprocess

from domain.health.models import VersionMetadata
from domain.health.providers import VersionMetadataProvider


class GitCommandMixin:
    @staticmethod
    def run_git_command(*args: str) -> str | None:
        try:
            completed = subprocess.run(
                ["git", *args],
                check=True,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None

        return completed.stdout.strip() or None


class GitHubActionsVersionMetadataProvider(GitCommandMixin, VersionMetadataProvider):
    def provide(self) -> VersionMetadata | None:
        if os.getenv("GITHUB_ACTIONS") != "true":
            return None

        commit_sha = os.getenv("GITHUB_SHA")
        branch = os.getenv("GITHUB_REF_NAME")
        build_number = os.getenv("GITHUB_RUN_NUMBER")
        workflow_run_id = os.getenv("GITHUB_RUN_ID")
        workflow_name = os.getenv("GITHUB_WORKFLOW")

        git_version = self.run_git_command("describe", "--tags", "--always", "--dirty")
        if git_version is None:
            git_version = commit_sha[:7] if commit_sha else None

        return VersionMetadata(
            git_version=git_version,
            commit_sha=commit_sha,
            branch=branch,
            source="github_actions",
            build_number=build_number,
            workflow_run_id=workflow_run_id,
            workflow_name=workflow_name,
        )


class AzureBuildVersionMetadataProvider(GitCommandMixin, VersionMetadataProvider):
    def provide(self) -> VersionMetadata | None:
        build_number = os.getenv("BUILD_BUILDNUMBER")
        if build_number is None:
            return None

        return VersionMetadata(
            git_version=self.run_git_command("describe", "--tags", "--always", "--dirty"),
            commit_sha=os.getenv("BUILD_SOURCEVERSION") or self.run_git_command("rev-parse", "HEAD"),
            branch=os.getenv("BUILD_SOURCEBRANCHNAME"),
            source="azure_pipelines",
            build_number=build_number,
            workflow_run_id=os.getenv("BUILD_BUILDID"),
            workflow_name=os.getenv("BUILD_DEFINITIONNAME"),
        )


class LocalGitVersionMetadataProvider(GitCommandMixin, VersionMetadataProvider):
    def provide(self) -> VersionMetadata | None:
        git_version = self.run_git_command("describe", "--tags", "--always", "--dirty")
        commit_sha = self.run_git_command("rev-parse", "HEAD")
        branch = self.run_git_command("rev-parse", "--abbrev-ref", "HEAD")

        if git_version is None and commit_sha is None and branch is None:
            return None

        return VersionMetadata(
            git_version=git_version,
            commit_sha=commit_sha,
            branch=branch,
            source="git",
            build_number=os.getenv("BUILD_BUILDNUMBER") or os.getenv("GITHUB_RUN_NUMBER"),
            workflow_run_id=os.getenv("BUILD_BUILDID") or os.getenv("GITHUB_RUN_ID"),
            workflow_name=os.getenv("BUILD_DEFINITIONNAME") or os.getenv("GITHUB_WORKFLOW"),
        )
