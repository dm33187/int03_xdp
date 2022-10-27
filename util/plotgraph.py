import matplotlib.pyplot as plt
import json

dictionary = json.load(open('qfactor.json', 'r'))

xAxis = []
yAxis = []

for elem in range(len(dictionary)):
    xAxis.extend([int(dictionary[elem]['delta'])])
    mystr = dictionary[elem]['value']
    mylist = mystr.split()
#    a = int(mylist[2])
    yAxis.extend([int(mylist[2])])

print(xAxis)
print(yAxis)

plt.grid(True)

## LINE GRAPH ##
plt.plot(xAxis,yAxis, color='maroon', marker='o')
plt.xlabel('delta in secs')
plt.ylabel('net.ipv4.tcp_wmem (max value)')

## BAR GRAPH ##
"""
fig = plt.figure()
plt.bar(xAxis,yAxis, color='maroon')
plt.xlabel('variable')
plt.ylabel('value')
"""
plt.show()
