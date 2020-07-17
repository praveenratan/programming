#Decorators

'''
# Dec is a funct, which takes fun as arg adds funct, returns another fun, without altering source code of actuall function
def outer_function(msg):
    #message  = 'Hi'
    #message = msg
    def inner_function():
        print(msg)
    return inner_function
#inner function waiting to be executed
hi_func = outer_function('Hi')
bye_func = outer_function('Bye')


hi_func()
bye_func()
'''


 #display is the func to be executed.
def dec_function(original_function):
    #def wrapper_function():
    def wrapper_function(*args, **kwargs):
        print('Wrapper Executed before {}'.format(original_function.__name__))
        return original_function()
    return wrapper_function

@dec_function
def display():
    print('display func ran')

#dec-display var
#dec_display = dec_function(display)

#dec_display()
#display()

@dec_function
def display_info(name, age):
    print('display_info ran with args {},{}'.format(name,age))

display()
display_info('Raja',29)