package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// setCondition merges newCond into conds using conditionType as the key,
// preserving LastTransitionTime when status is unchanged.
func setCondition(conds []metav1.Condition, newCond metav1.Condition) []metav1.Condition {
	for i, c := range conds {
		if c.Type == newCond.Type {
			if c.Status == newCond.Status {
				newCond.LastTransitionTime = c.LastTransitionTime
			}
			conds[i] = newCond
			return conds
		}
	}
	return append(conds, newCond)
}
