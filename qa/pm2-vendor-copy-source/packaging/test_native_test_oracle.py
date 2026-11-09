import unittest
from native_test_oracle import complete_native_suite


class NativeTestOracle(unittest.TestCase):
    def test_full_requested_suite_and_native_markers_required(self):
        log = '=== RUN   TestOne\n--- PASS: TestOne (0.01s)\n=== RUN   TestChild\n--- SKIP: TestChild (0.00s)\nactual ABI verified\nactual private lifecycle verified\nPASS\nFinished with result: success\n'
        expected = ['TestOne', 'TestChild']
        markers = ['actual ABI verified', 'actual private lifecycle verified']
        self.assertTrue(complete_native_suite(log, expected, markers, ['TestChild']))
        for changed in [log.replace('actual private lifecycle verified', ''), log.replace('PASS\nFinished', 'Finished'), log.replace('--- PASS: TestOne (0.01s)\n', ''), log.replace('=== RUN   TestOne\n', ''), log + 'Main processes terminated with: code=killed, status=15/TERM\n', log + 'PASS\n']:
            self.assertFalse(complete_native_suite(changed, expected, markers, ['TestChild']))
        self.assertFalse(complete_native_suite(log, expected, markers))
        self.assertFalse(complete_native_suite(log, expected + ['TestOne'], markers, ['TestChild']))

    def test_zero_result_after_stopped_compiler_is_not_acceptance(self):
        interrupted = '=== RUN   TestAnalyticsHTMLNativeModuleAndActualResponses\nprivate QuickJS compiler started\nFinished with result: success\nMain processes terminated with: code=killed, status=15/TERM\n'
        self.assertFalse(complete_native_suite(interrupted, ['TestAnalyticsHTMLNativeModuleAndActualResponses'], ['PASS 32 actual HTTP response cases']))


if __name__ == '__main__':
    unittest.main()
