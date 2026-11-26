"""The recovery calls: every call a run makes beyond the planned ones, asked_again + 2 x splits, counted
by kind (an ask-again after an omission, one after an unreadable reply, a split half).

The planned calls are one per batch and question asked, plus the adjustments. On a complete run the run summary's
counters give the total; on a failed run a split whose first half stopped the run made one call less, so the calls
are counted from the archive there.
"""
from chain import calls as callmod
from chain import venslog


def _count(kinds, *wanted):
    return sum(1 for k in kinds if k in wanted)


def breakdown(summary, recs, archived, kinds, failed):
    """summary: the run summary or None; recs: the log's records or None; archived: the archived calls or None;
    kinds: their classification (None entries where unclassified); failed: whether the attempt failed, None when
    not known. Every figure a source does not give is None."""
    out = {"llm_calls": None, "asked_again": None, "splits": None, "archived_calls": None, "planned": None,
           "adjustment": None, "again_omission": None, "again_unreadable": None, "split_halves": None,
           "recovery_calls": None, "source": None, "problems": []}
    if summary is not None:
        out.update(llm_calls=summary.get("llm_calls"), asked_again=summary.get("asked_again"),
                   splits=summary.get("splits"))
    classified = archived is not None and kinds is not None and None not in kinds
    if archived is not None:
        out["archived_calls"] = len(archived)
    if classified:
        out.update(planned=_count(kinds, callmod.PLANNED, callmod.ADJUSTMENT),
                   adjustment=_count(kinds, callmod.ADJUSTMENT),
                   again_omission=_count(kinds, callmod.AGAIN_OMISSION),
                   again_unreadable=_count(kinds, callmod.AGAIN_UNREADABLE),
                   split_halves=_count(kinds, callmod.HALF))
    formula = None
    if out["asked_again"] is not None and out["splits"] is not None:
        formula = out["asked_again"] + 2 * out["splits"]
    from_archive = _count(kinds, *callmod.RECOVERY) if classified else None

    if formula is not None and (failed is False or out["splits"] == 0):
        out.update(recovery_calls=formula, source="summary")
    elif from_archive is not None:
        out.update(recovery_calls=from_archive, source="archive")

    if recs is not None:
        by_log = venslog.ask_agains(recs)
        log_kinds = {venslog.OMISSION: 0, venslog.UNREADABLE_KIND: 0}
        for _, kind in by_log:
            log_kinds[kind] += 1
        if classified and (log_kinds[venslog.OMISSION], log_kinds[venslog.UNREADABLE_KIND]) != (
                out["again_omission"], out["again_unreadable"]):
            out["problems"].append(f"ask-agains by kind: log {log_kinds}, archive "
                                   f"{{'omission': {out['again_omission']}, 'unreadable': {out['again_unreadable']}}}")
        if not classified:
            out.update(again_omission=log_kinds[venslog.OMISSION], again_unreadable=log_kinds[venslog.UNREADABLE_KIND])
        if out["splits"] is not None and venslog.splits(recs) != out["splits"]:
            out["problems"].append(f"splits: summary {out['splits']}, log {venslog.splits(recs)}")
        if not classified and out["splits"] is not None and (failed is False or out["splits"] == 0):
            out["split_halves"] = 2 * out["splits"]

    if formula is not None and from_archive is not None and failed is False and formula != from_archive:
        out["problems"].append(f"recovery calls: summary {formula}, archive {from_archive}")
    if out["llm_calls"] is not None and archived is not None and out["llm_calls"] != len(archived):
        out["problems"].append(f"llm_calls {out['llm_calls']}, archived calls {len(archived)}")
    total = out["llm_calls"] if out["llm_calls"] is not None else out["archived_calls"]
    if out["planned"] is None and total is not None and out["recovery_calls"] is not None:
        out["planned"] = total - out["recovery_calls"]
    return out
