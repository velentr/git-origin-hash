;;; SPDX-FileCopyrightText: 2023 Brian Kubisiak <brian@kubisiak.com>
;;;
;;; SPDX-License-Identifier: GPL-3.0-only

(use-modules (g-hooks core)
             (g-hooks utils)
             (g-hooks library))

(g-hooks
 (commit-msg gitlint/commit-msg)
 (pre-commit
  (hooks
   reuse-lint/pre-commit
   rustfmt/pre-commit)))
