# Discovering vulnerabilities in Python web applications

## 1\. Problem

A large class of vulnerabilities in applications originates in programs that enable user input information to affect the values of certain parameters of security sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions **or variables** (so called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions **or variables**, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.

It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restricting the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.

The aim of this project is to study how web vulnerabilities can be detected statically by means of taint and input sanitization analysis. We choose as a target web server side programs encoded in the Python language. There exist a range of Web frameworks for Python, of which Django is the most widely used. While examples in this project specification often refer to Django views, the problem is to be understood as generic to the Python language.

The following references are mandatory reading about the problem:

- S. Micheelsen and B. Thalmann, "PyT - A Static Analysis Tool for Detecting Security Vulnerabilities in Python Web Applications", Master's Thesis, Aalborg University 2016
- V. Chibotaru et. al, "Scalable Taint Specification Inference with Big Code", PLDI 2019 Note: This paper contains a large component of machine learning that is not within the scope of this course, and which you may skip through.
- L. Giannopoulos et. al, "Pythia: Identifying Dangerous Data-flows in Django-based Applications", EuroSec 2019

## 2\. Specification of the Tool

The experimental part consists in the development of a static analysis tool for identifying data and information flow violations that are not protected in the program. In order to focus on the flow analysis, the aim is not to implement a complete tool. Instead, it will be assumed that the code to be analyzed has undergone a pre-processing stage to isolate, in the form of a program slice, a sequence of Python instructions that are considered to be relevant to our analysis.

The following code slice, which is written in Python, contains code lines which may impact a data flow between a certain entry point and a sensitive sink. The variable `request` (which for intuition can be seen as the request parameter of a Django view), is uninstantiated, and can be understood as an entry point. It uses the `MySQLCursor.execute()` method, which executes the given database operation query.

```python
uname = retrieve_uname(request)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
```

Inspecting this slice it is clear that the program from which the slice was extracted can potentially encode a SQL injection vulnerability. An attacker can inject a malicious username like `' OR 1 = 1 -- ` modifying the structure of the query and obtaining all users' passwords.

The aim of the tool is to search the slices for vulnerabilities according to inputted patterns, which specify for a given type of vulnerability its possible sources (a.k.a. entry points), sanitizers and sinks. A _pattern_ is thus a 5-tuple with:

- name of vulnerability (e.g., SQL injection)
- a set of entry points (e.g., `get`),
- a set of sanitization functions (e.g., `escape_string`),
- a set of sensitive sinks (e.g., `execute`),
- and a flag indicating whether implicit flows are to be considered.

The tool should signal potential vulnerabilities and sanitization efforts: if it identifies a possible data flow from an entry point to a sensitive sink (according to the inputted patterns), it should report a potential vulnerability; if the data flow passes through a sanitization function (in other words, it is returned by the function), _it should still report the vulnerability_, but also acknowledge the fact that its sanitization is possibly being addressed.

We provide program slices and patterns to assist you in testing the tool. It is however each group's responsibility to perform more extensive testing for ensuring the correctness and robustness of the tool. Note however that for the purpose of testing, the names of vulnerabilities, sources, sanitizers and sinks are irrelevant and do not need to be real vulnerabilities. In this context, you can produce your own patterns without specific knowledge of vulnerabilities, as this will not affect the ability of the tool to manage meaningful patterns. See examples in Section [Input Vulnerability Patterns](#input-vulnerability-patterns).

### Running the tool

The tool should be called in the command line, and receive the following two arguments, and only the following two arguments:

- the name of a Python file containing the program slice to analyse;
- the name of a [JSON](http://www.json.org/) file containing the list of vulnerability patterns to consider.

You can assume that the parsing of the Python slices has been done, and that the input files are [well-formed](#input-program-slices). The analysis should be fully customizable to the inputted [vulnerability patterns](#input-vulnerability-patterns) described below. In addition to the entry points specified in the patterns, **by default any non-instantiated variable that appears in the slice is to be considered as an entry point to all vulnerabilities being considered**.

The output should list the potential vulnerabilities encoded in the slice, and an indication of which sanitization functions(s) (if any) have been applied. The format of the output is specified [below](#output).

Your tool should be implemented in **Python, version >= 3.9.2**, and work in the following way:

1. be named `py_analyser.py`
2. be called in the command line with two arguments `<slice>.py` and `<patterns>.json`
3. produce the output referred below and no other to a file named `<slice>.output.json` in the `./output/` folder.

For example

    $ python ./py_analyser.py slice_1.py my_patterns.json

should analyse `slice_1.py` slice, according to patterns in file `my_patterns.json`, and output the result in file `./output/slice_1.output.json`.

NOTE: Scripts that validate the correct format of the pattern and output files will be made available during the first week of the project.

### Input

#### Program slices

Your program should read from a text file (given as first argument in the command line) the representation of a Python slice.  See [below](#processing) how you can easily convert it into an Abstract Syntax Tree (AST).

#### Vulnerability patterns

The patterns are to be loaded from a file, whose name is given as the second argument in the command line. You can assume that pattern names are unique.

An example JSON file with three patterns:

    [
      {"vulnerability": "SQL injection A",
      "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
      "sanitizers": ["mogrify", "escape_string"],
      "sinks": ["execute"],
      "implicit": "no"},

      {"vulnerability": "SQL injection B",
      "sources": ["QueryDict", "ContactMailForm", "ChatMessageForm", "copy", "get_query_string"],
      "sanitizers": ["mogrify", "escape_string"],
      "sinks": ["raw", "RawSQL"],
      "implicit": "yes"},

      {"vulnerability": "XSS",
      "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
      "sanitizers": ["clean", "escape", "flatatt", "render_template", "render", "render_to_response"],
      "sinks": ["send_mail_jinja", "mark_safe", "Response", "Markup", "send_mail_jinja", "Raw"],
      "implicit": "no"}
    ]

### Processing

The Python file (given as first argument in the command line) containing the Python slice should be converted into an Abstract Syntax Tree (AST).

You can use Python's `ast` module to obtain a tree of objects whose classes all inherit from [ast.AST](https://docs.python.org/3/library/ast.html). The tool can work directly on this ast using the module's utility functions.

You can also opt to work on a simplified representation of the AST where nodes are represented using dictionaries and lists. To this end, you can use

```python
ast_py = ast.parse(py_str)
ast_dict = astexport.export.export_dict(ast_py)
```

In the above, `py_str` is the string containing the Python code, and `ast_dict` is a dictionary encoding of the ast that represents the code.
The AST is represented in JSON, using the same structure as in [Python's AST module](https://docs.python.org/3.10/library/ast.html).

The structure of Python's ASTs varies slightly with different Python versions. The examples below use Python 3.9 -- as in the labs, similar to 3.8 and 3.10. For instance, the program

```python
print("Hello World!")
```

is represented as

    {
        "ast_type": "Module",
        "body": [
            {
                "ast_type": "Expr",
                "col_offset": 0,
                "end_col_offset": 21,
                "end_lineno": 1,
                "lineno": 1,
                "value": {
                    "args": [
                        {
                            "ast_type": "Constant",
                            "col_offset": 6,
                            "end_col_offset": 20,
                            "end_lineno": 1,
                            "kind": null,
                            "lineno": 1,
                            "value": "Hello World!"
                        }
                    ],
                    "ast_type": "Call",
                    "col_offset": 0,
                    "end_col_offset": 21,
                    "end_lineno": 1,
                    "func": {
                        "ast_type": "Name",
                        "col_offset": 0,
                        "ctx": {
                            "ast_type": "Load"
                        },
                        "end_col_offset": 5,
                        "end_lineno": 1,
                        "id": "print",
                        "lineno": 1
                    },
                    "keywords": [],
                    "lineno": 1
                }
            }
        ],
        "type_ignores": []
    }

and the slice

```python
uname = retrieve_uname(request)
q = cursor.execute("SELECT pass FROM users WHERE user='%s'" % uname)
```

is represented as:

    {
        "ast_type": "Module",
        "body": [
            {
                "ast_type": "Assign",
                "col_offset": 0,
                "end_col_offset": 31,
                "end_lineno": 1,
                "lineno": 1,
                "targets": [
                    {
                        "ast_type": "Name",
                        "col_offset": 0,
                        "ctx": {
                            "ast_type": "Store"
                        },
                        "end_col_offset": 5,
                        "end_lineno": 1,
                        "id": "uname",
                        "lineno": 1
                    }
                ],
                "type_comment": null,
                "value": {
                    "args": [
                        {
                            "ast_type": "Name",
                            "col_offset": 23,
                            "ctx": {
                                "ast_type": "Load"
                            },
                            "end_col_offset": 30,
                            "end_lineno": 1,
                            "id": "request",
                            "lineno": 1
                        }
                    ],
                    "ast_type": "Call",
                    "col_offset": 8,
                    "end_col_offset": 31,
                    "end_lineno": 1,
                    "func": {
                        "ast_type": "Name",
                        "col_offset": 8,
                        "ctx": {
                            "ast_type": "Load"
                        },
                        "end_col_offset": 22,
                        "end_lineno": 1,
                        "id": "retrieve_uname",
                        "lineno": 1
                    },
                    "keywords": [],
                    "lineno": 1
                }
            },
            {
                "ast_type": "Assign",
                "col_offset": 0,
                "end_col_offset": 68,
                "end_lineno": 2,
                "lineno": 2,
                "targets": [
                    {
                        "ast_type": "Name",
                        "col_offset": 0,
                        "ctx": {
                            "ast_type": "Store"
                        },
                        "end_col_offset": 1,
                        "end_lineno": 2,
                        "id": "q",
                        "lineno": 2
                    }
                ],
                "type_comment": null,
                "value": {
                    "args": [
                        {
                            "ast_type": "BinOp",
                            "col_offset": 19,
                            "end_col_offset": 67,
                            "end_lineno": 2,
                            "left": {
                                "ast_type": "Constant",
                                "col_offset": 19,
                                "end_col_offset": 59,
                                "end_lineno": 2,
                                "kind": null,
                                "lineno": 2,
                                "value": "SELECT pass FROM users WHERE user='%s'"
                            },
                            "lineno": 2,
                            "op": {
                                "ast_type": "Mod"
                            },
                            "right": {
                                "ast_type": "Name",
                                "col_offset": 62,
                                "ctx": {
                                    "ast_type": "Load"
                                },
                                "end_col_offset": 67,
                                "end_lineno": 2,
                                "id": "uname",
                                "lineno": 2
                            }
                        }
                    ],
                    "ast_type": "Call",
                    "col_offset": 4,
                    "end_col_offset": 68,
                    "end_lineno": 2,
                    "func": {
                        "ast_type": "Attribute",
                        "attr": "execute",
                        "col_offset": 4,
                        "ctx": {
                            "ast_type": "Load"
                        },
                        "end_col_offset": 18,
                        "end_lineno": 2,
                        "lineno": 2,
                        "value": {
                            "ast_type": "Name",
                            "col_offset": 4,
                            "ctx": {
                                "ast_type": "Load"
                            },
                            "end_col_offset": 10,
                            "end_lineno": 2,
                            "id": "cursor",
                            "lineno": 2
                        }
                    },
                    "keywords": [],
                    "lineno": 2
                }
            }
        ],
        "type_ignores": []
    }

Note that not all of the information that is available in the AST needs necessarily to be used and stored by your program. This [tutorial](https://greentreesnakes.readthedocs.io/en/latest/) is a helpful resource.

You can produce your own ASTs for testing your program by using a [python-to-json parser](https://pypi.org/project/astexport/). You can visualize the JSON outputs as a tree using [this online tool](http://jsonviewer.stack.hu/).

### Output

The output of the program is a `JSON` list of vulnerability objects that should be written to a file `./output/<slice>.output.json` where `<slice>.py` is the program slice under analysis. The structure of the objects should include 5 pairs, with the following meaning:

- `vulnerability`: name of vulnerability (string, according to the inputted pattern)
- `source`: input source (string, according to the inputted pattern, and line where it appears in the code)
- `sink`: sensitive sink (string, according to the inputted pattern, and line where it appears in the code)
- `unsanitized_flows`: whether there are unsanitized flows (string)
- `sanitized_flows`: sanitizing functions (string, according to the inputted pattern,  and line where it appears in the code) if present, otherwise empty (list of lists of strings)

As an example, the output with respect to the program and patters that appear in the examples in [Specification of the Tool](#3-specification-of-the-tool) would be:

    [{"vulnerability": "SQL injection A",
    "source": ("request", 1),
    "sink": ("execute", 2),
    "unsanitized_flows": "yes",
    "sanitized_flows": []}]

The output list must include a vulnerability object for every pair source-sink between which there is at least one flow of information. If at least one of the flows is not sanitized, it must be signaled. Since it is possible that there are more than one flow paths for a given pair source-sink, that could be sanitized in different ways, sanitized flows are represented as a list. Since each flow might be sanitized by more than one sanitizer, each flow is itself a list (with no particular order).

More precisely, the format of the output should be:

    <OUTPUT> ::= [ <VULNERABILITIES> ]
    <VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>, <VULNERABILITIES>
    <VULNERABILITY> ::= { "vulnerability": "<STRING>",
                        "source": ("<STRING>", <INT>)
                        "sink": ("<STRING>", <INT>),
                        "unsanitized_flows": <YESNO>,
                        "sanitized_flows": [ <FLOWS> ] }
    <YESNO> ::= "yes" | "no"
    <FLOWS> ::= "none" | <FLOW> | <FLOW>, <FLOWS>
    <FLOW> ::= [ <SANITIZERS> ]
    <SANITIZERS> ::= (<STRING>, <INT>) | (<STRING>, <INT>), <SANITIZERS>

_Note_: A flow is said to be sanitized if it goes "through" an appropriate sanitizer, i.e., if at some point the entire information is converted into the output of a sanitizer.

### Precision and scope

The security property that underlies this project is the following:

_Given a set of vulnerability patterns of the form (vulnerability name, a set of entry points, a set of sensitive sinks, a set of sanitizing functions), a program is secure if it does not encode, for any given vulnerability pattern, an information flow from an entry point to a sensitive sink, unless the information goes through a sanitizing function._

You will have to make decisions regarding whether your tool will signal, or not, illegal taint flows that are encoded by certain combinations of program constructs. You can opt for an approach that simplifies the analysis. This simplification may introduce or omit features that could influence the outcome, thus leading to wrong results.

Note that the following criteria will be valued:

- _Soundness_ - successful detection of illegal taint flows (i.e., true positives). In particular, treatment of implicit taint flows will be valued.
- _Precision_ - avoiding signalling programs that do not encode illegal taint flows (i.e., false-positives). In particular, sensitivity to the order of execution will be valued.
- Scope - treatment of a larger subset of the language. The mandatory language constructs are those that appear in the slices provided, and include: assignments, binary operations, function calls, condition test and while loop.

Using the same terms as in [Python Parser](https://docs.python.org/3/library/ast.html) the mandatory constructs are those associated with nodes of type

- Expressions
  - Constant
  - Name
  - BinOp, UnaryOp
  - BoolOp, Compare
  - Call
  - Attribute
- Statements
  - Expr
  - Assign
  - If
  - While

When designing and implementing this component, you are expected to take into account and to incorporate precision and efficiency considerations, as presented in the critical analysis criteria below.
