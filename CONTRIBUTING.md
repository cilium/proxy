# Contributing to cilium/proxy

The `cilium/proxy` repository is a minimal fork of the **Envoy Proxy** project. Its primary purpose is to integrate necessary **Cilium-specific filters and extensions** that cannot yet be upstreamed or are highly specific to Cilium's architecture.

Our goal is to remain as close to upstream Envoy as possible. Therefore, we highly encourage an **"upstream-first"** contribution policy.

### 1. Upstream-First Contributions (Recommended)

For the health of this project and the broader community, if your contribution falls into any of the following categories, **please contribute it directly to the official [Envoy Proxy repository](https://github.com/envoyproxy/envoy)**:

* General bug fixes.
* Performance improvements.
* New general-purpose features or functionality.
* Updates to core code or existing standard filters.
* Build system improvements that benefit all Envoy users.

This approach ensures the Cilium project benefits from the standard community review process and helps reduce maintenance overhead in this fork.

### 2. Cilium-Specific Contributions

Contributions to the `cilium/proxy` repository should be limited to code that is **strictly necessary for Cilium's functionality**, primarily:

* New Cilium-specific L7 network filters.
* Modifications required for deep Cilium integration (e.g., changes for a Cilium-specific API).
* Updates to the repository's build system/scripts required for Cilium's consumption.

#### Submitting a Contribution

1.  **Open an Issue:** Before starting any significant work, please open an issue to discuss your proposed change.
2.  **Fork and Branch:** Fork this repository and create a new branch for your feature or fix.
3.  **Submit a Pull Request (PR):**
    * Ensure your code follows existing style conventions.
    * If the change relates to a known issue or a PR you submitted upstream, **please link to the relevant upstream Envoy issue or PR** in your submission.

### 3. Contributor Ladder

`cilium/proxy` is a sub-project of the Cilium project and follows the same governance model, community processes, and contributor growth paths as Cilium. To support contributors in gaining both privileges and responsibilities, we adopt the shared [Contributor Ladder](https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md). This contributor ladder defines how contributors can grow from community participants to project maintainers, along with the expectations at each level.

Community members generally start at the first levels of the ladder and advance as their involvement deepens. Becoming a Cilium organization member grants additional privileges across the project ecosystem, such as the ability to review pull requests or trigger CI runs. If you are contributing regularly to `cilium/proxy`, we encourage you to join the 
[Envoy team](https://github.com/cilium/community/blob/main/ladder/teams/envoy.yaml) to help review code and accelerate development.

Your contributions play a vital role in improving the project, and the community is here to support you every step of the way. Thank you for helping us maintain a minimal and effective fork!
