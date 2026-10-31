<h2 align="center">
  <a href=#><img src="https://raw.githubusercontent.com/armbian/.github/master/profile/logosmall.png" alt="Armbian logo"></a>
  <br><br>
</h2>

# Armbian Kernel Security Fixes

## Purpose of This Repository

An automatic backporting service for kernel security fixes. It targets the older LTS kernels **6.18**, **6.12** and **6.1**, and the newest stable, **7.3**.

Stable releases take weeks to carry a fix, and some fixes never reach an older LTS. This repository closes that gap.

`patches/<series>/` holds every known fix that the stable branch does not have yet:

- Each fix applies on the stable head, and the set builds.
- A fix that does not apply is backported with Claude. A person reviews the backport.
- A fix leaves the folder when the stable branch has it.

## Usage

Apply the patches in `series.conf` order on the commit in `base`.

## More

- Status: [report.md](report.md)
- Help with backports: [CONTRIBUTING.md](CONTRIBUTING.md)
- How it works: [DEVELOPMENT.md](DEVELOPMENT.md)
