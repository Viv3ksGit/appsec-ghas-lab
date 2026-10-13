/**
 * @name Subprocess call with shell=True
 * @description Org guardrail: any subprocess call with shell=True must be reviewed by AppSec,
 *              even when no tainted source is proven (catches what taint tracking can miss).
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id appsec-lab/python/subprocess-shell-true
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.ApiGraphs

from API::CallNode call
where
  call =
    API::moduleImport("subprocess")
        .getMember(["call", "run", "Popen", "check_call", "check_output", "getoutput"])
        .getACall() and
  call.getArgByName("shell").asExpr() instanceof True
select call, "subprocess call with shell=True; prefer an argument list and shell=False."
