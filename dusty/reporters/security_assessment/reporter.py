from dusty.models.module import DependentModuleModel
from dusty.models.reporter import ReporterModel
from dusty.tools import log
from .legacy import SecurityAssessmentApi
from .models import FindingCollection
import json

class Reporter(DependentModuleModel, ReporterModel):
    def __init__(self, context):
        """ Initialize reporter instance """
        super().__init__()
        self.context = context
        self.config = \
            self.context.config["reporters"][__name__.split(".")[-2]]

    def report(self):
        log.info(f"Sending report to Security Assessment System API...")
        api = SecurityAssessmentApi(self.config)
        api.scanner_finding(FindingCollection(self.config, self.context).findings)

    @staticmethod
    def fill_config(data_obj):
        """ Make sample config """
        data_obj.insert(len(data_obj), "api_url", "https://api_url.example.com", comment="Security Assessment System API URL")
        data_obj.insert(
            len(data_obj), "bearer_token", "bearer_token", comment="Bearer Token"
        )

    @staticmethod
    def validate_config(config):
        required = ["api_url", "bearer_token"]
        not_set = [item for item in required if item not in config]
        if not_set:
            error = f"Required configuration options not set: {', '.join(not_set)}"
            log.error(error)
            raise ValueError(error)

    @staticmethod
    def get_name():
        """ Reporter name """
        return "Security Assessment System"

    @staticmethod
    def get_description():
        """ Reporter description """
        return "Security Assessment System Reporter"