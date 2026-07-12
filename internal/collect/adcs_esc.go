package collect

// escInput carries the decoded template facts the ESC assessment needs.
type escInput struct {
	enrolleeSuppliesSubject bool
	allowsSAN               bool
	hasClientAuth           bool
	hasAnyPurpose           bool
	hasEnrollmentAgent      bool
	noSecurityExtension     bool
	managerApproval         bool
	authorizedSignatures    bool
	exportableKey           bool
	haveEnrollees           bool
	lowPrivEnroll           bool
	onlyAdmins              bool
	lowPrivWrite            bool
	ownerLowPriv            bool
}

// notCritHigh reports whether the risk is neither CRITICAL nor HIGH.
func notCritHigh(risk string) bool { return risk != "CRITICAL" && risk != "HIGH" }

// assessESC replicates PyADRecon-ADWS's ESC1–4/9 risk state machine, including
// its exact (mixed-case) risk-level labels and factor strings.
func assessESC(in escInput) (esc []string, risk string, factors []string) {
	risk = "Low"
	add := func(s string) { factors = append(factors, s) }

	// ESC1: enrollee supplies subject + client auth, enrollable by non-admins.
	if in.enrolleeSuppliesSubject && in.hasClientAuth && in.haveEnrollees && !in.onlyAdmins {
		esc = append(esc, "ESC1")
		switch {
		case in.managerApproval:
			if risk == "Low" {
				risk = "MEDIUM"
			}
			add("ESC1: Enrollee supplies subject + Client Auth (mitigated by manager approval)")
		case in.lowPrivEnroll:
			risk = "CRITICAL"
			add("ESC1: Enrollee supplies subject + Client Auth + Low-priv enrollment")
		default:
			risk = "HIGH"
			add("ESC1: Enrollee supplies subject + Client Auth")
		}
	}

	// ESC2: Any Purpose EKU.
	if in.hasAnyPurpose && in.haveEnrollees && !in.onlyAdmins {
		esc = append(esc, "ESC2")
		switch {
		case in.managerApproval:
			add("ESC2: Any Purpose EKU (mitigated by manager approval requirement)")
		case in.lowPrivEnroll:
			if risk != "CRITICAL" {
				risk = "HIGH"
			}
			add("ESC2: Any Purpose EKU allows arbitrary certificate usage")
		default:
			if notCritHigh(risk) {
				risk = "MEDIUM"
			}
			add("ESC2: Any Purpose EKU allows arbitrary certificate usage")
		}
	}

	// ESC3: Certificate Request Agent (Enrollment Agent) EKU.
	if in.hasEnrollmentAgent && in.haveEnrollees && !in.onlyAdmins {
		esc = append(esc, "ESC3")
		switch {
		case !in.managerApproval && !in.authorizedSignatures:
			if notCritHigh(risk) {
				risk = "HIGH"
				if !in.lowPrivEnroll {
					risk = "MEDIUM"
				}
			}
			add("ESC3: Certificate Request Agent EKU with no approval/signature requirements")
		case in.managerApproval && in.authorizedSignatures:
			add("ESC3: Certificate Request Agent EKU (mitigated by manager approval + authorized signatures)")
		case in.managerApproval || in.authorizedSignatures:
			mitigation := "authorized signatures"
			if in.managerApproval {
				mitigation = "manager approval"
			}
			add("ESC3: Certificate Request Agent EKU (partially mitigated by " + mitigation + ")")
		default:
			if notCritHigh(risk) {
				risk = "MEDIUM"
			}
			add("ESC3: Certificate Request Agent EKU")
		}
	}

	// ESC4: non-admin write access to the template.
	if in.lowPrivWrite {
		if notCritHigh(risk) {
			risk = "HIGH"
		}
		esc = append(esc, "ESC4")
		add("ESC4: Non-admin principals have write access to template")
	}

	// ESC9: no security extension + client auth + no approvals + low-priv enroll.
	if in.noSecurityExtension && in.hasClientAuth && !in.managerApproval &&
		!in.authorizedSignatures && in.lowPrivEnroll {
		esc = append(esc, "ESC9")
		if notCritHigh(risk) {
			risk = "HIGH"
		}
		add("ESC9: No security extension + Client Auth + No approvals (allows certificate theft & impersonation)")
	}

	// Additional informational factors.
	if in.onlyAdmins && in.enrolleeSuppliesSubject && in.hasClientAuth {
		add("ESC1 config present but only admins can enroll")
	}
	if in.enrolleeSuppliesSubject && !in.hasClientAuth && risk == "Low" && !in.onlyAdmins {
		risk = "Medium"
		add("Enrollee can supply subject name")
	} else if in.allowsSAN && risk == "Low" && !in.onlyAdmins {
		risk = "Medium"
		add("Allows Subject Alternative Name")
	}
	if in.exportableKey && risk != "Low" {
		add("Private key exportable")
	}
	if in.lowPrivEnroll && in.haveEnrollees && risk == "Low" {
		add("Low-privileged users can enroll")
	}

	// Owner-based ESC4 variant.
	if in.ownerLowPriv {
		if notCritHigh(risk) {
			risk = "HIGH"
		}
		if !containsStr(esc, "ESC4") {
			esc = append(esc, "ESC4")
		}
		add("ESC4: Low-privileged owner can modify template")
	}

	if len(esc) == 0 && len(factors) == 0 {
		risk = "None"
	}
	return esc, risk, factors
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
