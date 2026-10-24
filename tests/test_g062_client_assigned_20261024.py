# -*- coding: utf-8 -*-
r"""G-062 resurrection, honest scope (2026-10-24).

Of the quarantined ``business_logic_patterns.py``, only two shapes can be
proved without semantic analysis; the rest (``skip_payment``,
``auto_approve``, ``negative_balance``, ``double_spend`` ...) match
IDENTIFIER NAMES, so a control mention and a control absence are the same
text to a regex -- the negative fixture problem is unfixable and those
patterns stay quarantined, now on principle rather than by oversight.

What resurfaces as findings, red-first (positives below were observed
failing before the rules existed):

  CLIENT_ASSIGNED_AMOUNT   price/amount/discount/order_total assigned from a
                           REQUEST BODY (request.json/form/get_json, req.body,
                           $_POST). Body-only is the provable boundary: a
                           query-string amount is most often a list filter,
                           while a body amount is a payment value the server
                           must never trust. Safe code assigns totals from
                           computed/catalog state, and those twins stay dark.
  CLIENT_ASSIGNED_PRIVILEGE
                           role/is_admin/permissions/account_status assigned
                           from a request body. TAINT_MASS_ASSIGNMENT only
                           fires when an entity sink (create/update/save or
                           Role/Admin token) is in the window; this catches
                           the direct field write itself.

Both reuse the proven family ``mass_assignment`` (CWE-915) for privilege and
a new ``client_controlled_amount`` remediation family (CWE-471) for money.
"""
import textwrap


def _write(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _sast(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# CLIENT_ASSIGNED_AMOUNT
# ---------------------------------------------------------------------------

def test_py_amount_from_json_body_fires(tmp_path):
    findings = _sast(tmp_path, "checkout.py", """\
        def create_order(request):
            amount = request.json["amount"]
            return charge(amount)
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" in _ids(findings), sorted(_ids(findings))


def test_js_price_from_body_fires(tmp_path):
    findings = _sast(tmp_path, "order.js", """\
        app.post("/order", (req, res) => {
          const price = req.body.price;
          res.json({ price });
        });
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" in _ids(findings), sorted(_ids(findings))


def test_php_discount_from_post_fires(tmp_path):
    findings = _sast(tmp_path, "apply.php", """\
        <?php
        $discount = $_POST['discount'];
        echo $discount;
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" in _ids(findings), sorted(_ids(findings))


def test_py_amount_from_server_side_total_stays_dark(tmp_path):
    findings = _sast(tmp_path, "checkout.py", """\
        def create_order(request):
            amount = cart.compute_total()
            return charge(amount)
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" not in _ids(findings), sorted(_ids(findings))


def test_js_price_from_catalog_stays_dark(tmp_path):
    findings = _sast(tmp_path, "order.js", """\
        app.post("/order", (req, res) => {
          const price = BOOK_PRICE * quantity;
          res.json({ price });
        });
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" not in _ids(findings), sorted(_ids(findings))


def test_py_query_filter_max_price_stays_dark(tmp_path):
    findings = _sast(tmp_path, "search.py", """\
        def search(request):
            max_price = request.args.get("max")
            return Item.objects.filter(price__lte=max_price)
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" not in _ids(findings), sorted(_ids(findings))


def test_php_get_price_filter_stays_dark(tmp_path):
    findings = _sast(tmp_path, "search.php", """\
        <?php
        $price = $_GET['p'];
        render_results($price);
        """)
    assert "CLIENT_ASSIGNED_AMOUNT" not in _ids(findings), sorted(_ids(findings))


# ---------------------------------------------------------------------------
# CLIENT_ASSIGNED_PRIVILEGE
# ---------------------------------------------------------------------------

def test_py_is_admin_from_json_body_fires(tmp_path):
    findings = _sast(tmp_path, "profile.py", """\
        def update_profile(request):
            user.is_admin = request.json["is_admin"]
            user.save()
        """)
    assert "CLIENT_ASSIGNED_PRIVILEGE" in _ids(findings), sorted(_ids(findings))


def test_js_role_from_body_fires(tmp_path):
    findings = _sast(tmp_path, "user.js", """\
        app.put("/user", (req, res) => {
          account.role = req.body.role;
          res.sendStatus(200);
        });
        """)
    assert "CLIENT_ASSIGNED_PRIVILEGE" in _ids(findings), sorted(_ids(findings))


def test_py_role_constant_stays_dark(tmp_path):
    findings = _sast(tmp_path, "signup.py", """\
        def signup(request):
            user.role = "user"
            user.save()
        """)
    assert "CLIENT_ASSIGNED_PRIVILEGE" not in _ids(findings), sorted(_ids(findings))


def test_py_is_admin_false_stays_dark(tmp_path):
    findings = _sast(tmp_path, "signup.py", """\
        def signup(request):
            user.is_admin = False
            user.save()
        """)
    assert "CLIENT_ASSIGNED_PRIVILEGE" not in _ids(findings), sorted(_ids(findings))
