"""IDOR: an invoice is fetched by a request-supplied id with no ownership
predicate anywhere in the handler, so any caller can read any object."""
from django.http import HttpResponse

from .models import Invoice


def invoice_detail(request):
    invoice = Invoice.objects.get(pk=request.GET["id"])
    return HttpResponse(invoice.body)
