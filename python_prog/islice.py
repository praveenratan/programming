import itertools

#files are actually iterators themselves
#we pass the file as f as 1st line and grab 3 lines)


with open('test.log', 'r') as f:
    header = itertools.islice(f,3)

    for line in header:
        #line itself has newline char init. we ignore by adding end = ''
        print(line,end ='')
