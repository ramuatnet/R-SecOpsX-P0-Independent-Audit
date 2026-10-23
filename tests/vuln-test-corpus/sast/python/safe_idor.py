"""Same fetch, but the ownership predicate is part of the query itself: the
database can only return the row the caller actually owns."""
from django.http import HttpResponse

from .models import Invoice


def invoice_detail(request):
    invoice = Invoice.objects.get(pk=request.GET["id"], owner=request.user)
    return HttpResponse(invoice.body)
