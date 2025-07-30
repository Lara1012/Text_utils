# HTTP GET :
#--> The GET method is the default submission method for a form.
#--> The GET method sends the data in the form of URL parameters. Therefore, any data sent with the help of the GET method remains visible in the URL. 
#--> Since the data is exposed in the URL, the GET method is not considered for sending sensitive information such as passwords.
#--> The GET method reveals the data in the URL bar; therefore, the length of the URL increases. The maximum URL length is 2048 characters, so only a limited amount of data can be sent using the GET method. The following error occurs when we try to send more than 2048 characters using GET :


# What if we do not want to show the text in the URL?


# Ans: If we do not want to expose the data in the URL bar, we can use the POST method instead of GET. Let's start our discussion on the POST method :


# POST :
# Data sent by the POST method never gets visible in the URL box, and therefore it is more secure than the GET method, and sensitive information can be sent with the help of this method.
# Since the data is not visible in the URL query, the length of the URL remains less than 2048 characters, and a large amount of data can be sent with the help of the POST method.
# Data is sent to the server in the form of packages in a separate communication with the processing script.
# Now, we will start our discussion on CSRF tokens.

# WHAT ARE CSRF TOKENS?
# CSRF stands for Cross-Site Request Forgery.
# The server-side application generates and transmits a huge, random, and unpredictable number to the client to make sure that the request is coming from the original client and not from a malicious website.
# CSRF tokens are used to protect the site against CSRF attacks.

from django.http import HttpResponse
from django.shortcuts import render

def index(request):
    return render(request, 'index.html')


def analyze(request):
    #Get the text
    djtext = request.POST.get('text', 'default')

    # Check checkbox values
    removepunc = request.POST.get('removepunc', 'off') # replace all the request.GET.get with the request.POST.get
    fullcaps = request.POST.get('fullcaps', 'off')
    newlineremover = request.POST.get('newlineremover', 'off')
    extraspaceremover = request.POST.get('extraspaceremover', 'off')

    #Check which checkbox is on
    if removepunc == "on":
        punctuations = '''!()-[]{};:'"\,<>./?@#$%^&*_~'''
        analyzed = ""
        for char in djtext:
            if char not in punctuations:
                analyzed = analyzed + char

        params = {'purpose':'Removed Punctuations', 'analyzed_text': analyzed}
        djtext = analyzed

    if(fullcaps=="on"):
        analyzed = ""
        for char in djtext:
            analyzed = analyzed + char.upper()

        params = {'purpose': 'Changed to Uppercase', 'analyzed_text': analyzed}
        djtext = analyzed

    if(extraspaceremover=="on"):
        analyzed = ""
        for index, char in enumerate(djtext):
            if not(djtext[index] == " " and djtext[index+1]==" "):
                analyzed = analyzed + char

        params = {'purpose': 'Removed NewLines', 'analyzed_text': analyzed}
        djtext = analyzed

    if (newlineremover == "on"):
        analyzed = ""
        for char in djtext:
            if char != "\n" and char!="\r":
                analyzed = analyzed + char

        params = {'purpose': 'Removed NewLines', 'analyzed_text': analyzed}

    if(removepunc != "on" and newlineremover!="on" and extraspaceremover!="on" and fullcaps!="on"):
        return HttpResponse("please select any operation and try again")

    return render(request, 'analyze.html', params)


