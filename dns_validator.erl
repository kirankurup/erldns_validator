-module (dns_validator).
-author ('kirankurup@gmail.com').

%% Reference:- http://www.zytrax.com/books/dns/ch15/

-export ([validate/2]).

-define (DOMAIN_DELIM,            <<".">>).
-define (DNS_SERVER_PORT,         53).
-define (LOCAL_PORT,              8000).


validate (InputFile, DNSServerIP) ->
  case parse (InputFile) of
    {error, _Reason} ->
      {error, invalid_file};
    ParsedInput ->
      %io:format ("Parsed input is ~p~n", [ParsedInput]),
      {ok, Socket} = gen_udp:open(?LOCAL_PORT, [binary]),
      {ok, ResultDesc} = file:open("result", [write]),
      Fun = fun (X={_IP, DomainName}, _Acc) ->
        validate_single_entry(X, DomainName, Socket, DNSServerIP, ResultDesc)
            end,
      lists:foldl(Fun, [], ParsedInput),
      gen_udp:close (Socket),
      file:close (ResultDesc)
  end.

parse (FileName) ->
  case file:read_file(FileName) of
    {ok, FileBin} ->
      UncommentedList = [X || <<First:8, _T/binary>> = X <- binary:split (FileBin, <<"\n">>, [global]), First =/= $#],
      Indiv = [re:split(X, "\\s*,\\s*") || X <- UncommentedList],
      TupleFirst = [list_to_tuple(X) || X <- Indiv],
      [{binary_to_list(X), Y} || {X, Y} <- TupleFirst];
    {error, Reason} ->
      io:format ("Invalid Input file ~p~n", [FileName]),
      {error, Reason}
  end.

validate_single_entry ({IPAddress, OrigDomainName}, NewDomainName, Socket, Server, OutFileDesc) ->
  ID = rand:uniform(1 bsl 16),
  Query = create_query(ID, NewDomainName),
  %io:format ("Query is ~p~n", [Query]),
  gen_udp:send(Socket, Server, ?DNS_SERVER_PORT, Query),
  receive
    {udp, Socket, _IP, _InPortNo, Packet = <<ID:16, _/binary>>} ->
      %io:format ("validate_single_entry: Response: ~p~n", [Packet]),
      case decode_response_message (Packet) of
        {ok, Val} when is_binary(Val) ->
          try
            ServerIPAddress = inet_parse:ntoa(erlang:list_to_tuple(binary_to_list(Val))),
            case IPAddress =:= ServerIPAddress of
              true ->
                %io:format ("validate_single_entry: Input: ~p, ~p.. Matches result from Server ~p~n", [IPAddress, DomainName, ServerIPAddress]),
                io:fwrite(OutFileDesc, "~s, ~s, ~s, match~n", [IPAddress, OrigDomainName, ServerIPAddress]),
                match;
              false ->
                %io:format ("validate_single_entry: Input: ~p, ~p.. Does not Match result from Server~p~n", [IPAddress, DomainName, ServerIPAddress]),
                io:fwrite(OutFileDesc, "~s, ~s, ~s, nomatch~n", [IPAddress, OrigDomainName, ServerIPAddress]),
                nomatch
            end
          catch
            _Err:_Reason ->
              io:fwrite(OutFileDesc, "~s, ~s, ~s, nomatch~n", [IPAddress, OrigDomainName, "error"]),
              nomatch
          end;
        {error, ErrReason} ->
          io:fwrite(OutFileDesc, "~s, ~s, ~s, nomatch~n", [IPAddress, OrigDomainName, ErrReason]),
          nomatch;
        {ok, cname, Str} ->
          validate_single_entry ({IPAddress, OrigDomainName}, Str, Socket, Server, OutFileDesc);
        _ ->
          io:fwrite(OutFileDesc, "~s, ~s, ~s, nomatch~n", [IPAddress, OrigDomainName, "error"]),
          nomatch
      end
  end.

create_label (Label) ->
  <<0:2, (byte_size(Label)):6, Label/binary>>.

create_query(ID, Domain) ->
  Header = <<ID:16,

    0:1,  %% QR = Query
    0:4,  %% OPCODE = Query
    0:1,  %% AA
    0:1,  %% TC
    1:1,  %% RD
    0:1,  %% RA
    0:3,  %% Z,
    0:4,  %% RCode
    1:16, %% QDCount
    0:16, %% ANCount
    0:16, %% NSCount
    0:16>>, %% ARCount
  QueryName = [create_label(Label) || Label <- binary:split(Domain, ?DOMAIN_DELIM, [global])],
  QuerySection = [QueryName, <<0:8,    %% Final Length Octet
    1:16,   %% QType,
    1:16>>],  %% QClass, IN
  [Header, QuerySection].

%% Pointer format
%% A-Type (Value of Type field 1)
decode_resource_record(<<3:2, _:6, _:8, 1:16, _Class:16, _TTL:32, RDLength:16, RData:RDLength/binary, _Rest/binary>>) ->
  %io:format ("AType String ~p~n", [RData]),
  {ok, RData};

%% CNAME-Type (Value of Type field 5)
decode_resource_record(<<3:2, _:6, _:8, 5:16, _Class:16, _TTL:32, RDLength:16, RData:RDLength/binary, _Rest/binary>>) ->
  {Str, _} = decode_string([], RData, true),
  %io:format ("CNAME String ~p~n", [Str]),
  {ok, cname, list_to_binary(Str)}.

decode_response_message (Response) ->
  <<_ID:16, 1:1,  %% QR = Response
    _OPCODE:4,  %% OPCODE =
    _AA:1,  %% AA
    _TC:1,  %% TC
    _RD:1,  %% RD
    _RA:1,  %% RA
    0:3,  %% Z,
    RCode:4,  %% RCode
    _QDC:16, %% QDCount
    _ANC:16, %% ANCount
    _NSC:16, %% NSCount
    _ARC:16, Body/binary>> %% ARCount
  = Response,
  case RCode of
    0 ->
      %% Continue
      decode_response_body (Body);
    _ ->
      %io:format ("Invalid Response Code: ~p~n", [RCode]),
      {error, invalid_response_code}
  end.

decode_response_body (Body) ->
  QSLessBody = discard_question_section (Body),
  decode_resource_record(QSLessBody).

discard_question_section (Body) ->
  {_QueryStr, QueryLessBody} = decode_string([], Body, false),
  <<_QType:16, _QClass:16, QuestionSectionLessBody/binary>> =  QueryLessBody,
  QuestionSectionLessBody.

decode_string (Str, <<0:8, Rest/binary>>, _AddDelim) ->
  {Str, Rest};
decode_string (Str, <<>>, _AddDelim) ->
  {Str, <<>>};
decode_string (Str, <<Len:8, Label:Len/binary, Rest/binary>>, AddDelim) ->
  NewStr = case AddDelim of
             true ->
               case Str of
                 [] ->
                   binary_to_list(Label);
                 _ ->
                   Str ++ binary_to_list(?DOMAIN_DELIM) ++ binary_to_list(Label)
               end;
             false ->
               Str ++ binary_to_list(Label)
           end,
  decode_string (NewStr, Rest, AddDelim).