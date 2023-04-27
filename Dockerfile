FROM tailucas/base-app:20230217
# for system/site packages
USER root
# system setup
# https://github.com/inter169/systs/blob/master/alpine/crond/README.md
RUN apk update \
    && apk upgrade \
    && apk --no-cache add \
        gcc \
        musl-dev
# cron jobs
RUN rm -f ./config/cron/base_job
# apply override
RUN /opt/app/app_setup.sh
# switch to user
USER app
# override configuration
COPY config/app.conf ./config/app.conf
COPY poetry.lock pyproject.toml ./
RUN /opt/app/python_setup.sh
# add the project application
COPY app/__main__.py ./app/
# apply override
CMD ["/opt/app/entrypoint.sh"]
