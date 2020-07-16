#comb - all diff ways to group and order dosenot matter
#per - order does matter
import operator
import itertools
#import snip

letters = ['a','b','c']
numbers = [1,2,3,4,0]
names = ['Raja', 'Praveen']

#keeps the running total of the passed iter
#result = itertools.accumulate(numbers)
#result = itertools.accumulate(numbers,operator.mul)




#a,b and b,a matters
#result = itertools.combinations(letters,2)

#print all diff ways a,b and b,a also gets printed
#result = itertools.permutations(letters,2)


#result = itertools.product(numbers,repeat=4)
#result = itertools.combinations_with_replacement(numbers,4)

#inefficent what if list contains many items
#combined = letters + numbers + names

#chain
#combined = itertools.chain(letters,numbers,names)

#slicing on iterator
#islice
#result = itertools.islice(range(10),5)
#one arg is stop point

#start,stop args
#result = itertools.islice(range(10),1,5)

#step
#result = itertools.islice(range(10),1,5,2)

#compress fun will return and iterable that has all valies of corresponding values that has Ture 
#selectors = [True,True, False,True]
#result = itertools.compress(letters,selectors)
#SIMLIAR filter uses fun to use true or false, but compress we pass in as arg

#itertools.filterfalse -> returns values that are not true
#itertools.filter -> returns the values that are true
#dropwhile -> drops values until it returns true.
#takewhile -> take values that are true until it returns false.



for item in result:
    print(item)

