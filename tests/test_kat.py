"""KAT reader: slicing sm into signature + message."""

import textwrap

from sqvcost.kat import load_kat


def test_load_kat_slices_signature(tmp_path):
    # sm = signature (4 bytes) || message; signature_bytes=4
    rsp = textwrap.dedent(
        """\
        # SQIsign_test

        count = 0
        seed = ABCD
        mlen = 2
        msg = AABB
        pk = 0102
        sk = 0304
        smlen = 6
        sm = DEADBEEFAABB

        count = 1
        seed = EF01
        mlen = 2
        msg = 1122
        pk = 0506
        sk = 0708
        smlen = 6
        sm = CAFEBABE1122
        """
    )
    p = tmp_path / "k.rsp"
    p.write_text(rsp)
    recs = load_kat(str(p), signature_bytes=4)
    assert len(recs) == 2
    assert recs[0].sig_hex == "DEADBEEF"
    assert recs[0].msg_hex == "AABB"
    assert recs[0].pk_hex == "0102"
    assert recs[1].sig_hex == "CAFEBABE"


def test_load_kat_limit(tmp_path):
    rec = "count = {i}\nmlen = 1\nmsg = AA\npk = 01\nsk = 02\nsmlen = 2\nsm = BBAA\n"
    text = "# h\n\n" + "\n".join(rec.format(i=i) for i in range(5))
    p = tmp_path / "k.rsp"
    p.write_text(text)
    recs = load_kat(str(p), signature_bytes=1, limit=3)
    assert len(recs) == 3
