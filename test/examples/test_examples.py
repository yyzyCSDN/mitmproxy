from mitmproxy import contentviews
from mitmproxy import io
from mitmproxy.addons import dns_replay
from mitmproxy.http import Headers
from mitmproxy.test import taddons
from mitmproxy.test import tflow
from mitmproxy.test import tutils


class TestScripts:
    def test_add_header(self, tdata):
        with taddons.context() as tctx:
            a = tctx.script(tdata.path("../examples/addons/anatomy2.py"))
            f = tflow.tflow()
            a.request(f)
            assert f.request.headers["myheader"] == "value"

    def test_custom_contentviews(self, tdata):
        with taddons.context() as tctx:
            tctx.script(tdata.path("../examples/addons/contentview.py"))
            swapcase = contentviews.registry["swapcase"]
            result = swapcase.prettify(b"<html>Test!</html>", contentviews.Metadata())
            assert "tEST!" in result

    def test_modify_form(self, tdata):
        with taddons.context() as tctx:
            sc = tctx.script(tdata.path("../examples/addons/http-modify-form.py"))

            form_header = Headers(content_type="application/x-www-form-urlencoded")
            f = tflow.tflow(req=tutils.treq(headers=form_header))
            sc.request(f)

            assert f.request.urlencoded_form["mitmproxy"] == "rocks"

            f.request.headers["content-type"] = ""
            sc.request(f)
            assert list(f.request.urlencoded_form.items()) == [("foo", "bar")]

    def test_modify_querystring(self, tdata):
        with taddons.context() as tctx:
            sc = tctx.script(
                tdata.path("../examples/addons/http-modify-query-string.py")
            )
            f = tflow.tflow(req=tutils.treq(path="/search?q=term"))

            sc.request(f)
            assert f.request.query["mitmproxy"] == "rocks"

            f.request.path = "/"
            sc.request(f)
            assert f.request.query["mitmproxy"] == "rocks"

    def test_redirect_requests(self, tdata):
        with taddons.context() as tctx:
            sc = tctx.script(tdata.path("../examples/addons/http-redirect-requests.py"))
            f = tflow.tflow(req=tutils.treq(host="example.org"))
            sc.request(f)
            assert f.request.host == "mitmproxy.org"

    def test_send_reply_from_proxy(self, tdata):
        with taddons.context() as tctx:
            sc = tctx.script(tdata.path("../examples/addons/http-reply-from-proxy.py"))
            f = tflow.tflow(req=tutils.treq(host="example.com", port=80))
            sc.request(f)
            assert f.response.content == b"Hello World"

    def test_dns_replay(self, tdata, tmp_path):
        dr = dns_replay.DnsReplay()
        with taddons.context(dr) as tctx:
            sc = tctx.script(tdata.path("../examples/addons/dns-replay.py"))

            sc.running()
            assert tctx.options.dns_replay_extra == "refuse"

            # an unreadable file does not raise and keeps the (empty) set
            sc.dns_replay_swap("/nonexistent")
            assert dr.count() == 0

            path = tmp_path / "dns.mitm"
            with open(path, "wb") as f:
                io.FlowWriter(f).add(tflow.tdnsflow(resp=True))
            sc.dns_replay_swap(str(path))
            assert dr.count() == 1

            # a failed replacement keeps the previous set
            sc.dns_replay_swap("/nonexistent")
            assert dr.count() == 1
