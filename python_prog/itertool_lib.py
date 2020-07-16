import itertools



#counter = itertools.cycle(('On','Off'))
#counter = itertools.cycle([1,2,3,4])

counter = itertools.repeat(2,times=3)

#squares = map(pow,range(10),itertools.repeat(2))

squares = itertools.starmap(pow,[(0,2),(1,2),(2,2)])
print(list(squares))


'''

#counter = itertools.count()

counter = itertools.count(start=5, step=2)



data = [100,200,300,400]

#daily_data = list(zip(range(10),data))
daily_data = list(itertools.zip_longest(range(10),data))

print (daily_data)
print(next(counter))
print(next(counter))
print(next(counter))
print(next(counter))
print(next(counter))
print(next(counter))
print(next(counter))
print(next(counter))

'''
