package bf.fasoshield.agent

import bf.fasoshield.agent.scan.Finding
import bf.fasoshield.agent.scan.Heuristics
import bf.fasoshield.agent.scan.Scoring
import bf.fasoshield.agent.scan.Severity
import bf.fasoshield.agent.scan.Verdict
import com.google.common.truth.Truth.assertThat
import org.junit.Test

class ScoringTest {

    private fun finding(sev: Severity) = Finding("r.${sev.name}", sev.name, sev, "d")

    @Test
    fun emptyFindingsAreClean() {
        val (verdict, score) = Scoring.verdictOf(emptyList())
        assertThat(verdict).isEqualTo(Verdict.CLEAN)
        assertThat(score).isEqualTo(0)
    }

    @Test
    fun singleCriticalIsMalicious() {
        val (verdict, score) = Scoring.verdictOf(listOf(finding(Severity.CRITICAL)))
        assertThat(verdict).isEqualTo(Verdict.MALICIOUS)
        assertThat(score).isEqualTo(100)
    }

    @Test
    fun oneMediumIsSuspicious() {
        // MEDIUM alone = 25 < 30, stays CLEAN; MEDIUM + LOW = 35 -> SUSPICIOUS.
        val (v1, _) = Scoring.verdictOf(listOf(finding(Severity.MEDIUM)))
        assertThat(v1).isEqualTo(Verdict.CLEAN)
        val (v2, score) = Scoring.verdictOf(listOf(finding(Severity.MEDIUM), finding(Severity.LOW)))
        assertThat(v2).isEqualTo(Verdict.SUSPICIOUS)
        assertThat(score).isEqualTo(35)
    }

    @Test
    fun scoreIsCappedAt100() {
        val many = List(5) { finding(Severity.HIGH) }
        val (_, score) = Scoring.verdictOf(many)
        assertThat(score).isEqualTo(100)
    }

    @Test
    fun similarityRanksLookalikesHigh() {
        val ratio = Heuristics.similarity("com.orange.money", "com.orange.rnoney")
        assertThat(ratio).isAtLeast(0.88)
        val unrelated = Heuristics.similarity("com.orange.money", "com.spotify.music")
        assertThat(unrelated).isLessThan(0.6)
    }
}
