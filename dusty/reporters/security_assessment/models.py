import re
from dusty.tools import log
from dusty.models.finding import DastFinding, SastFinding
from dusty.constants import SEVERITIES

class Finding:
    def __init__(self, summary, description, severity, status="", resolution="", endpoints=list(),
                 component="", line="", url="", cwe=list(), tags=list(), scanner="", confidence=""):
        self.summary = summary
        self.description = description
        self.severity = severity
        self.status = status
        self.resolution = resolution
        self.endpoints = endpoints
        self.component = component
        self.line = line
        self.url = url
        self.cwe = cwe
        self.tags = tags
        self.scanner = scanner
        self.confidence = confidence


class FindingCollection:
    def __init__(self, config, context):
        self.config = config
        self.findings = list()

        for item in context.findings:
            if not isinstance(item, (DastFinding, SastFinding)):
                log.warning("Unsupported finding type")
            self.findings.append(
                Finding(
                    summary=item.title,
                    description=self.__get_description(item),
                    severity=self.__get_severity(item.get_meta("severity", SEVERITIES[-1]).upper()),
                    endpoints=[endpoint.raw for endpoint in item.get_meta("endpoints", list())],
                    line=item.get_meta('legacy.line', ""),
                    cwe=item.get_meta('legacy.cwe', []),
                    tags=[
                        label.replace(" ", "_") for label in [
                            item.get_meta("tool", "scanner"),
                            context.get_meta("testing_type", "DAST"),
                            item.get_meta("severity", SEVERITIES[-1])
                        ]
                    ] + self.__get_dynamic_label(item),
                    scanner=item.get_meta('scanner_type', ""),
                    confidence=item.get_meta('confidence', "")
                ).__dict__
            )

    def __get_dynamic_label(self, item):
        dynamic_label_mapping = dict()
        if self.config.get("dynamic_labels", None):
            try:
                for key, value in self.config.get("dynamic_labels").items():
                    dynamic_label_mapping[re.compile(key)] = value
            except:  # pylint: disable=W0702
                log.exception("Failed to add dynamic label mapping")

        dynamic_labels = list()
        for endpoint in item.get_meta("endpoints", list()):
            for pattern, addon_label in dynamic_label_mapping.items():
                try:
                    if pattern.match(endpoint.raw):
                        dynamic_labels.append(addon_label)
                except:  # pylint: disable=W0702
                    log.exception("Failed to add dynamic label")

        return dynamic_labels

    @staticmethod
    def __get_description(item):
        description = ''
        if isinstance(item, DastFinding):
            description = item.description.replace("\\.", ".")
        elif isinstance(item, SastFinding):
            description = ".".join(item.description).replace("\\.", ".")

        return description

    @staticmethod
    def __get_severity(severity):
        if severity == "INFO":
            return "INFORMAL"
        return severity