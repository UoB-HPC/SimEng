Developer information
=====================

Contributions in the form of GitHub pull requests are always welcome.
Pull requests will be reviewed carefully, and changes may be requested if they
do not adhere to the guidelines below.

Any given pull request should deliver a single small feature or bug fix.
Large pieces of new functionality should be broken up into multiple pull
requests that incrementally build up the desired functionality, in order to
expedite the code review process and minimise disruption for other people
working on the codebase.
Please discuss large functionality changes with the core development team
before starting to work on them, to ensure that the new code will align with
the overall direction of SimEng and to avoid duplicated work.


Coding style
------------

New contributions should always adhere to the SimEng coding style.
It should generally be possible to glean the coding style from the existing
code, but there is also a ``.clang_format`` file that helps automate the
process of checking the formatting.
The recommendation is to run ``git-clang-format`` after staging changes to
ensure the changes will match the SimEng coding style.
Please avoid commits that solely change formatting; use ``git commit --amend``
or ``git commit --fixup`` to fold formatting changes into the commit that
introduced the code.

Code should be well commented.
New class and method declarations should use Doxygen ``/** */`` syntax to allow
documentation to be generated automatically.


Tests
-----
SimEng has an internal test suite that should be run before any pull request is
opened to ensure that there are no regressions.
Changes that add new functionality or fix serious bugs should almost always be
accompanied by new tests (or additions to existing tests where appropriate).

Further information about the internal test suite and guidance on adding new, or 
appending to existing, test cases can be found in the :doc:`Testing <test/index>` 
section of the developer documentation.

Currently, there are CircleCI and Jenkins configurations that will automatically 
test that each pull request builds and passes the test suite for multiple compilers 
before being merged. Those compilers include:

- GCC 7/8/9
- CLANG 5/7
- ARMCLANG 20

.. todo::

    Define testing processes for accuracy and performance


Commit style
------------

Commits should be atomic, with each commit introducing a single, self-contained
change.

Please use `meaningful commit messages
<https://chris.beams.io/posts/git-commit/#seven-rules>`_.

Please avoid merge commits; the git history should be linear.
`Rebase <https://git-scm.com/book/en/v2/Git-Branching-Rebasing>`_ your local
work onto the current main branch regularly to keep it up to date.


Directory structure
-------------------

``configs/``
    Pre-generated config files for specific processors

``docs/``
    Documentation for users and developers

``external/``
    Third-party dependencies, as submodules

``src/include/simeng/``
    Header files for publicly visible SimEng APIs

``src/lib/``
    Source code for core SimEng library

``src/tools/``
    Source code for SimEng executables
    
.. ``test/kernels/``
..     Tests for simulation accuracy and performance

``test/regression/``
    Regression test suite covering end-to-end simulator functionality

``test/unit/``
    Unit tests for core SimEng library


Documentation
-------------

Significant new features should generally also be accompanied by documentation 
provided using `Sphinx <http://www.sphinx-doc.org/en/master/>`_.
These docs are built and deployed to a
`GitHub Pages site <https://uob-hpc.github.io/SimEng>`_.

Building the documentation locally requires a few Sphinx packages, which are
simplest to install via ``pip``:
::

    pip install --user Sphinx m2r2 sphinx-rtd-theme

To build the docs, run ``cmake <path_to_docs_root>`` from the build directory 
to generate the associate Makefile followed by ``make docs``.
This will generate HTML documentation which can be found in
``<build_directory>/sphinx/index.html``.


.. todo::

    Doxygen documentation.
