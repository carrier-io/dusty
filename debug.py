# from multiprocessing import Process
#
# def func1(**kwargs):
#   print( 'func1: starting')
#   for i in range(1000):
#       print('func1: processing' + kwargs.get('string_value'))
#   kwargs.get('results').append('func1: finishing')
#
# def func2(**kwargs):
#   print( 'func1: starting')
#   for i in range(1000):
#       print('func2: processing' + kwargs.get('string_value'))
#   kwargs.get('results').append('func2: finishing')
#
# def runInParallel(*fns):
#     proc = []
#     for fn, kwargs in fns:
#         p = Process(target=fn, kwargs=(kwargs))
#         p.start()
#         proc.append(p)
#     for p in proc:
#         p.join()
#
#
# if __name__ == '__main__':
#
#     results = []
#     runInParallel((func1, {'string_value': 'string1', 'results' :results}),
#                   (func2, {'string_value': 'string2', 'results' :results}))
#     print(results)
import time
#
def foo1(bar, result):
    for _ in range(3):
        time.sleep(1)
        print('hello {0}'.format(bar))
    result.append("foo1")

def foo2(bar, result):
    for _ in range(3):
        time.sleep(1)
        print('hello {0}'.format(bar))
    result.append("foo2")

def foo3(bar, result):
    for _ in range(3):
        time.sleep(1)
        print('hello {0}'.format(bar))
    result.append("foo3")

from threading import Thread

def run_in_parrallel(*fns):
    threads = []

    for fn in fns:
        thread = Thread(target=fn)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()


results = []
run_in_parrallel(foo1('123', results),
                 foo2('234', results),
                 foo3('345', results))
print(" ".join(results))

# import threading
# import time
# threads = []
#
# print("hello")
#
# def doWork(i):
#     print( "i = ",i)
#     for j in range(0,i):
#         print("j = ",j)
#         time.sleep(5)
#
# for i in range(1,4):
#     thread = threading.Thread(target=doWork, args=(i,))
#     threads.append(thread)
#     thread.start()
#
# # you need to wait for the threads to finish
# for thread in threads:
#     thread.join()
#
# print("Finished")