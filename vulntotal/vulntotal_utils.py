#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import operator


class GenericVersion:
    def __init__(self, version):
        self.value = version
        self.decomposed = tuple([int(i) for i in version.split(".")])

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.value.__eq__(other.value)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.decomposed.__lt__(other.decomposed)

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__lt__(other) or self.__eq__(other)


def compare(version, gh_comparator, gh_version):
    operator_comparator = {
        "<": operator.lt,
        ">": operator.gt,
        "=": operator.eq,
        "<=": operator.le,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
    }
    compare = operator_comparator[gh_comparator]
    return compare(version, gh_version)


def parse_gh_onstraint(constraint):
    if constraint.startswith(("<=", ">=", "==", "!=")):
        return constraint[:2], constraint[2:]
    elif constraint.startswith(("<", ">", "=")):
        return constraint[0], constraint[1:]


def github_constraints_satisfied(github_constrain, version):
    gh_constraints = github_constrain.strip().replace(" ", "")
    constraints = gh_constraints.split(",")
    for constraint in constraints:
        gh_comparator, gh_version = parse_gh_onstraint(constraint)
        if not compare(GenericVersion(version), gh_comparator, GenericVersion(gh_version)):
            return False
    return True
