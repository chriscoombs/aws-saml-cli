#!/usr/bin/env bash
# Unset variables to prevent persistence across invocations
unset idp domain user account principal role realm mfa nosecure password credentials saml
OPTIND=1
while getopts :i:d:u:a:p:r:l:m:n:x:h flag; do
  case "${flag}" in
    i) idp=$OPTARG ;;
    d) domain=$OPTARG ;;
    u) user=$OPTARG ;;
    a) account=$OPTARG ;;
    p) principal=arn:aws:iam::$account:saml-provider/$OPTARG ;;
    r) role=arn:aws:iam::$account:role/$OPTARG ;;
    l) realm=$OPTARG ;;
    m) mfa=$OPTARG ;;
    n) nosecure=true ;;
    x) password=$OPTARG ;;
    h) echo -e "Invocation example:\n. ./adfs.sh -i your.idp.com -d domain.com -u user.name -a 012345678910 -p principal -r role -l your.realm.com -m 123456\n\nFlags:\n-i IdP URL\n-d Active directory domain URL\n-u Username\n-a AWS account ID\n-p IdP name\n-r Role\n-l Realm URL\n-m MFA Token\n-s Insecure mode\n-x Password" ;;
    *) echo "Unexpected option ${flag}"; exit 1 ;;
  esac
done
# Request password from user
if [[ "$password" == "" ]]; then
    echo "Password...";
    read -s password;
else
    echo "Warning! Using a password on the command line can be insecure."
fi
# For IdPs which present self-signed certificates
if [ "$nosecure" = true ]; then
    echo QUIT | openssl s_client -showcerts -connect $idp:443 -servername $idp > cacert.pem
    ip=$(dig +short $idp)
    insecure="--resolve $idp:443:$ip --cacert cacert.pem";
fi
# Get 302 URL and IdP cookies
url=$(curl -L --silent --cookie-jar idp.cookies --output /dev/null -w %{url_effective} --url "https://$idp/adfs/ls/idpinitiatedsignon.htm?logintoRP=urn:amazon:webservices&RedirectToIdentityProvider=http://$([ \"$realm\" == \"\" ] && echo $idp || echo $realm)/adfs/services/trust" $insecure);
# Post username and password to realm
curl -L --silent --cookie-jar auth.cookies --output response.html --data-urlencode "UserName=$domain\\$user" --data-urlencode "Password=$password" --data-urlencode "AuthMethod=FormsAuthentication" --url $url $insecure;
# If MFA was provided
if [[ "$mfa" != "" ]]; then
    context=$(grep -i context response.html | awk -F"\"" '{print $8}');
    # Post context and token to realm
    curl --silent --cookie auth.cookies --cookie-jar auth.cookies --data-urlencode "Context=$context" --data-urlencode "security_code=$mfa" --data-urlencode "username=" --data-urlencode "password=" --data-urlencode "AuthMethod=VIPAuthenticationProviderWindowsAccountName" --data-urlencode "Continue=Continue" --url $url $insecure;
    curl --silent --cookie auth.cookies --cookie-jar auth.cookies --output response.html --url $url $insecure;
fi
# Extract saml from realm response HTML
saml=$(cat response.html | awk -F'"' '{print $12}');
# If realm was provided
if [[ "$realm" != "" ]]; then
    # Extract RelayState from realm response HTML
    RelayState=$(cat response.html  | awk -F'"' '{print $18}');
    # Post saml and RelayState to IdP
    curl --silent --cookie idp.cookies --output response.html --data-urlencode "SAMLResponse=$saml" --data-urlencode "RelayState=$RelayState" --url "https://$idp/adfs/ls/" $insecure;
    # Extract saml from IdP response HTML
    saml=$(cat response.html | awk -F'"' '{print $12}');
fi
echo "Assuming Role With SAML for $account";
credentials=$(aws sts assume-role-with-saml --principal-arn $principal --role-arn $role --saml-assertion $saml);
echo "Exporting AWS Credentials";
export AWS_ACCESS_KEY_ID=$(echo $credentials | jq --raw-output .Credentials.AccessKeyId);
export AWS_SECRET_ACCESS_KEY=$(echo $credentials | jq --raw-output .Credentials.SecretAccessKey);
export AWS_SESSION_TOKEN=$(echo $credentials | jq --raw-output .Credentials.SessionToken);
echo "AWS Credentials Exported";
# Tidy up
rm -f idp.cookies auth.cookies response.html cacert.pem;
