example_policy = {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FullAdminWildcard",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "ServiceWildcardNoCondition",
      "Effect": "Allow",
      "Action": ["s3:*", "iam:PassRole"],
      "Resource": "*"
    },
    {
      "Sid": "NarrowActionSpecificResource",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::app-data-bucket/*"
    },
    {
      "Sid": "WildcardResourceButConditioned",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:RequestedRegion": "us-east-1" }
      }
    },
    {
      "Sid": "EmptyConditionBlock",
      "Effect": "Allow",
      "Action": "dynamodb:*",
      "Resource": "*",
      "Condition": {}
    },
    {
      "Sid": "NotActionAllowEverythingElse",
      "Effect": "Allow",
      "NotAction": "iam:*",
      "Resource": "*"
    },
    {
      "Sid": "DenyWildcardShouldNotFlag",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "SingleStringActionWildcardService",
      "Effect": "Allow",
      "Action": "kms:*",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
    }
  ]
}



def iam_analyzer(iam_policy: dict):
    iam_statements = iam_policy["Statement"]

    overly_broad_iam = set()
    statements = iam_statements if isinstance(iam_statements, list) else [iam_statements]
    for statement in statements:
        action_is_broad, resource_is_broad, no_condition = False, False, False
        if statement.get("Effect") != "Allow":
            continue
        if statement["Resource"] == "*" or ":*" in statement["Resource"]:
            resource_is_broad = True

        actions = statement.get("Action")
        if isinstance(actions, str):
          if actions == "*" or ":*" in actions:
              action_is_broad = True
        elif isinstance(actions, list):
            for action in actions:
                if action == "*" or ":*" in action:
                    action_is_broad = True

        if statement["Effect"] == "Allow":
            if statement.get("NotAction"):
                overly_broad_iam.add(statement["Sid"])

        condition = statement.get("Condition")
        if condition is None or isinstance(condition, dict) and len(condition) == 0:
            no_condition = True

        if action_is_broad and resource_is_broad and no_condition:
            overly_broad_iam.add(statement["Sid"])

    return(overly_broad_iam)

print(iam_analyzer(example_policy))
