#!/usr/bin/env python
import os
import sys
import pytest
import coverage

if __name__ == '__main__':
    # Environment variables
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'strongswan_manager.settings.local')

    measure_coverage = True
    if '--no-cov' in sys.argv:
        measure_coverage = False
        sys.argv.remove('--no-cov')

    def_args = ['strongswan_manager/apps', 'strongswan_manager/helper_apps', 'strongswan_manager/tests/tests']
    if '--no-vici' in sys.argv:
        def_args.append('--ignore=strongswan_manager/tests/tests/vici/')
        sys.argv.remove('--no-vici')

    # Start coverage tracking
    if measure_coverage:
        cov = coverage.coverage()
        cov.start()

    # Run pytest
    if len(sys.argv) > 1:
        code = pytest.main(sys.argv)
    else:
        code = pytest.main(def_args)

    # Show coverage report
    if measure_coverage:
        cov.stop()
        cov.save()
        cov.report()

    sys.exit(code)
