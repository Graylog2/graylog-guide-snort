# How to send Snort IDS alert logs into Graylog

This guide describes how to send structured Snort IDS alert logs into Graylog.

![](https://s3.amazonaws.com/graylogblog/snort_integration/dashboard.png)

A blog post with use-cases can be found on the Graylog Blog: [Visualize and Correlate IDS Alerts with Open Source Tools](https://www.graylog.org/post/visualize-and-correlate-ids-alerts-with-open-source-tools)

## Configuring Snort

First, instruct Snort to write all alerts to the local syslog daemon:

    # snort.conf
    output alert_syslog: LOG_LOCAL5 LOG_ALERT

Next, configure the local syslog daemon to forward logs to Graylog. If you are using rsyslog, it would look like the following:

    $template GRAYLOGRFC5424,"<%PRI%>%PROTOCOL-VERSION% %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%\n"
    
    local5.alert @graylog.example.org:514;GRAYLOGRFC5424

## Configuring Graylog

In Graylog, set up a UDP syslog input at the port and network interface you configured in rsyslog earlier and confirm that messages are arriving. For examples, you could enable ICMP IDS rules and ping a host you are monitoring with Snort to trigger an alert to arrive in Graylog.

You’ll notice that the alert information is not parsed by Graylog yet. We will set up a [Graylog Processing Pipeline](http://docs.graylog.org/en/latest/pages/pipelines.html) to identify snort logs and parse the alert into a message with extracted fields.

Below is the rule we are using:

```
rule "Extract Snort alert fields"
when
  has_field("message")
then
  let m = regex("\\[(\\d+):(\\d+):(\\d+)\\] (.+?) \\[Classification: (.+?)\\] \\[Priority: (\\d+)]: \\<(.+?)\\> \\{(.+?)\\} (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:(\\d{1,5}))? -> (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:(\\d{1,5}))?\\R?", to_string($message.message));

  set_field("snort_alert", true);

  set_field("generator_id", m["0"]);
  set_field("signature_id", m["1"]);
  set_field("signature_revision_id", m["2"]);

  set_field("description", m["3"]);
  set_field("classification", m["4"]);
  set_field("priority", to_long(m["5"]));
  set_field("protocol", m["7"]);

  set_field("src_addr", m["8"]);
  set_field("src_port", to_long(m["10"]));

  set_field("dst_addr", m["11"]);
  set_field("dst_port", to_long(m["13"]));
end
```

Then, connect this pipeline to a stream with the following rules to apply to all snort messages:

    # Stream "Snort Alerts"
    
    # Rule 1:
    message must match regular expression ^\s?\[\d+:\d+:\d+].*
   
    # Rule 2:
     application_name must match exactly snort

## Result

Now all Snort alerts should arrive in Graylog with nicely parsed and extracted fields:

![](https://s3.amazonaws.com/graylogblog/snort_integration/snort_message.png)
