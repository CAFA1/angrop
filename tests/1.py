#coding=utf-8 #coding:utf-8
class Parent(object):
   def myMethod(self):
      print ('调用父类方法')
      self.process()

class Child(Parent):
   def myMethod(self):
      print ('调用子类方法')
   def process(self):
      print 'here'

c = Child()
c.myMethod()
super(Child,c).myMethod()