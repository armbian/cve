<h2 align="center">
  <a href=#><img src="https://raw.githubusercontent.com/armbian/.github/master/profile/logosmall.png" alt="Armbian logo"></a>
  <br><br>
</h2>

# Armbian Kernel Security Fixes

## Purpose of This Repository

Kernel security fixes for Armbian, before the stable releases carry them.

`patches/<series>/` holds every known fix that the stable branch does not have yet:

- Each fix applies on the stable head, and the set builds.
- A fix that does not apply is backported with Claude. A person reviews the backport.
- A fix leaves the folder when the stable branch has it.

Series: **6.18** and **7.3**.

## Usage

Apply the patches in `series.conf` order on the commit in `base`.

## More

- Status: [report.md](report.md)
- Help with backports: [CONTRIBUTING.md](CONTRIBUTING.md)
- How it works: [DEVELOPMENT.md](DEVELOPMENT.md)
