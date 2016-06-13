import os
import sys

import argparse
from argparse import RawTextHelpFormatter
from vbox.tools.vmrun_cycled import run_sample, run_cycled
from vbox.tools.PyCommands.settings import RAW_DIR
from lib.pander import process_all_logs
from lib.seq_analyzer.local_alignment import test_match

def main():
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,
                                     description='Command line interface for '
                                     'invoking scan, parse, and analyze procedures'
                                     ' of current module.')
    parser.add_argument('-a', '--action', default='analyze_exe_sample',
                        help='Specify actions, one of: \n'
                        'analyze_exe_sample - default value, performs sample '
                        'scan, logs parsing and slow_comparison with kbase\n'
                        'analyze_seq - performs slow_comparison of ready '
                        'sequence with kbase and outputs html report\n\n'
                        'parse_log - performs parsing of ready log file, produced '
                        'by scan_exe, outputs npy which can later be used by '
                        'analyze_seq\n\n'
                        'scan_sample - performs launch in vbox and logs collection\n\n'
                        'add_to_kbase - performs scanning, parsing and add resulting'
                        ' sequence to current knowledge base\n\n'
                        'batch_scan - performs batch parallel scan of all samples in '
                        ' specified location, outputs to vbox/logs\n\n'
                        'batch_parse - performs batch parsing of all logs in target directory, '
                        'outputs to hdf5 file "test" directory\n\n'
                        'batch_analyze - performs fast_comparison of all sequences '
                        'in target directory with knowledge base')
    parser.add_argument('-t', '--target', required=True,
                        help='Select the target for specified action')
    args = parser.parse_args()
    action, target = args.action, args.target
    if action == 'analyze_seq':
        test_group = 'test'
        print('[!] Option analyze_seq was selected, processing specified sequence '
              'in "%s" directory.' % test_group)
        test_match(strategy='SLOW', test_group=test_group, match_one=target)
    elif action == 'parse_log':
        print('[!] Option parse_log was selected, processing specified log '
              'outputting to "test" directory of current hdf5 file')
        if not os.path.isfile(target):
            print('[-] Specified target file doesn\'t exist !')
            sys.exit(1)
        if not target.endswith('apicalls.log'):
            print('[-] Target file should be created by scan and it\'s usually'
                  ' named apicalls.log, if you renamed, please rename it back!')
            sys.exit(1)
        process_all_logs(source=target, target_group='test')
    elif action == 'scan_sample':
        print('[!] Option scan_exe was selected, collecting logs for specified '
              'sample zipped executable file.')
        if not os.path.isfile(target):
            print('[-] Specified target file doesn\'t exist !')
            sys.exit(1)
        if not target.endswith('.zip'):
            print('[-] Target file should be zipped!')
            sys.exit(1)
        target_logfile = run_sample(target)
        if not os.path.isfile(target_logfile):
            print('[-] Unfortunately, scanning produced no logs, terminating...')
            sys.exit(1)
        else:
            print('[+] Logs present in %s file.' % os.path.abspath(target_logfile))
    elif action == 'add_to_kbase':
        print('[!] Option add_to_kbase was selected, processing specified sample '
              'zipped executable file, parsing and adding result sequence into '
              'default knowledgebase file.')
        if not os.path.isfile(target):
            print('[-] Specified target file doesn\'t exist !')
            sys.exit(1)
        if not target.endswith('.zip'):
            print('[-] Target file should be zipped!')
            sys.exit(1)
        target_logfile = run_sample(target)
        if not os.path.isfile(target_logfile):
            print('[-] Unfortunately, scanning produced no logs, terminating...')
            sys.exit(1)
        process_all_logs(source=target_logfile, target_group='knowledgebase')
        print('[+] Succesfully added %s sequence to knowledgebase.' % target)
    elif action == 'batch_scan':
        print('[!] Option batch_scan selected, running scan of all samples in '
              'specified samples directory and outputting result into '
              'default logs directory vbox/logs...')
        if not os.path.isdir(target):
            print('[-] Specified target directory doesn\'t exist !')
            sys.exit(1)
        run_cycled(sample_dir=target)
        print('[+] Logs present in %s directory.' % RAW_DIR)
    elif action == 'batch_parse':
        print('[!]  Option batch_parse selected, running parse of all sample logs'
              ' in specified logs directory and outputting to "test" directory'
              ' of default knowledgebase file lib/seq_analyzer/datas/knowledgebase.hdf5')
        if not os.path.isdir(target):
            print('[-] Specified target directory doesn\'t exist !')
            sys.exit(1)
        process_all_logs(source=target, target_group='test')
    elif action == 'batch_analyze':
        print('[!] Option batch_analyze selected, running fast_comparison of '
              'all sequences in default "test" group of default knowledgebase '
              'file on current kbase')
        test_match(strategy='FAST', test_group=target)
    elif action == 'analyze_exe_sample':
        print('[!] Default option analyze_exe_sample selected, going to perform '
              'scan, parsing and analyze that sample on current knowledgebase.')
        if not os.path.isfile(target):
            print('[-] Specified target file doesn\'t exist !')
            sys.exit(1)
        if not target.endswith('.zip'):
            print('[-] Target file should be zipped!')
            sys.exit(1)
        target_logfile = run_sample(target)
        target_name = os.path.splitext(os.path.basename(target))[0]
        if not os.path.isfile(target_logfile):
            print('[-] Unfortunately, scanning produced no logs, terminating...')
            sys.exit(1)
        process_all_logs(source=target_logfile, target_group='test')
        test_match(strategy='SLOW',
                   test_group='test',
                   match_one=target_name)
    else:
        print('[-] Unknown action "%s" specified, terminating...' % action)
        sys.exit(1)


if __name__ == '__main__':
    main()
