import re
import glob
import os

valid = re.compile(r'(?P<funcname>\w+)\n(?P<funcdesc>[A-Z].+?\.)\n', re.DOTALL)
#valid = re.compile(r'\w+[\n]', re.DOTALL)
FILTERS_DIR =r'C:\Users\User\Downloads\winapioverride32_bin\monitoring files'


def yielder(iterator):
    returner = iter(iterator)
    ctr = 0
    for val in returner:
        if not any(deny in val for deny in ('Appendix', 'Important Windows Functions')):
            yield val
            ctr += 1

def filter_apis():
    with open('API_parsed.txt', 'w') as outp, open('API_USAGE.txt') as inp:
        wholedict = dict()
        whole = inp.read()
        for match in valid.finditer(whole):
            that = match.groupdict()
            that['funcdesc'] = that['funcdesc'].replace('\n', ' ')
            wholedict[that['funcname']] = that['funcdesc']
            #print('|{funcname}| """{funcdesc}"""'.format(**that))
    return wholedict


def make_filter_file():
    filtered = filter_apis()
    for eachfilter in glob.glob(FILTERS_DIR + '\\*.txt'):
        print('finding .. %s' % eachfilter)
        with open(eachfilter) as inp, open('our_%s' % os.path.basename(eachfilter), 'w') as outp:
            print(os.path.abspath('our_%s' % os.path.basename(eachfilter)))
            for line in inp:
                if any(key in line for key in filtered):
                    print("FOUND SOME : %s " % (line))
                    outp.write(line)

assert False, filter_apis().keys()
#make_filter_file()
        
