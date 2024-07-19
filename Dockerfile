FROM tailucas/base-app:latest
# for system/site packages
USER root
# generate correct locales
ARG LANG
ENV LANG ${LANG}
ARG LANGUAGE
ENV LANGUAGE ${LANGUAGE}
ARG LC_ALL
ENV LC_ALL ${LC_ALL}
ARG ENCODING
RUN localedef -i ${LANGUAGE} -c -f ${ENCODING} -A /usr/share/locale/locale.alias ${LANG}
# system setup
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        html-xml-utils \
        sqlite3
# user scripts
COPY backup_db.sh .
# cron jobs
RUN rm -f ./config/cron/base_job
COPY config/cron/backup_db ./config/cron/
# apply override
RUN /opt/app/app_setup.sh
# override application
# add the project application
COPY app/ ./app/
# override configuration
COPY config/app.conf ./config/app.conf
COPY poetry.lock pyproject.toml ./
RUN chown app:app poetry.lock
# switch to run user
USER app
RUN /opt/app/python_setup.sh
# override entrypoint
COPY app_entrypoint.sh .
CMD ["/opt/app/entrypoint.sh"]
