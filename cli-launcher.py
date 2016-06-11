import argparse
from argparse import RawTextHelpFormatter
from vbox.tools.vmrun_cycled import run_sample
from lib.pander import fileparse
from lib.seq_analyzer.local_alignment import test_match

def main():
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
                                     description='Command line interface for '
                                     'invoking scan, parse, and analyze procedures'
                                     ' of current module.')
    parser.add_argument('--action', default='analyze_exe_sample',
                        help='Specify actions, one of: \n'
                        'analyze_exe_sample - default value, performs sample '
                        'scan, logs parsing and slow_comparison with kbase\n'
                        'analyze_seq - performs slow_comparison of ready npy '
                        'sequence with kbase and outputs html report\n\n'
                        'parse_logs - performs parsing of ready logs, produced '
                        'by scan_exe, outputs npy which can later be used by '
                        'analyze_seq\n\n'
                        'scan_exe - performs launch in vbox and logs collection\n\n'
                        'add_to_kbase - performs scanning, parsing and add resulting'
                        ' sequence to current knowledge base\n\n'
                        'batch_scan - performs batch parallel scan of all samples in '
                        ' default location vbox/samples, outputs to vbox/logs\n\n'
                        'batch_parse - performs batch parsing of all logs in vbox/logs, '
                        'outputs to hdf5 file "test" directory\n\n'
                        'batch_analyze - performs fast_comparison of all sequences '
                        'in "test" directory with knowledge base')
    args = parser.parse_args()
    action = args.action
    if action == 'analyze_exe_sample':
        pass
    elif action == 'analyze_seq':
        pass
    elif action == 'parse_logs':
        pass
    elif action == 'scan_exe':
        pass
    elif action == 'add_to_kbase':
        pass
    elif action == 'batch_scan':
        pass
    elif action == 'batch_parse':
        pass
    elif action == 'batch_analyze':
        pass

if __name__ == '__main__':
    main()
